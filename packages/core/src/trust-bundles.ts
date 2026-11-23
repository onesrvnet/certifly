import { type Executor, schema } from '@certifly/db'
import { certificateToPem, inspectCertificate, parseCertificateBundle } from '@certifly/pki'
import { and, asc, desc, eq, inArray, isNull } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import { CA_SLUG_PATTERN } from './cas'
import type { Context } from './context'
import { randomToken, safeEqualHex, sha256 } from './crypto'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { AppError, AuthenticationError, AuthorizationError, ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, trustBundlePolicy } from './policies'
import { TRAEFIK_CLIENT_AUTH_TYPES, TRAEFIK_NAME_PATTERN, traefikConfig } from './traefik'

export type TrustBundleRow = typeof schema.trustBundles.$inferSelect

/** A bundle is for one trust store; this many CAs is far more than any needs. */
export const MAX_BUNDLE_CAS = 50

const subjectOf = (id: string) => ({ type: 'trust_bundle', id })

/** The public URL of a bundle's PEM, built from `PKI_BASE_URL`. */
export function trustBundleUrl(ctx: Context, slug: string) {
  return `${ctx.pki_base_url}/api/pki/bundle/${slug}.pem`
}

/** The public URL of a bundle's Traefik dynamic configuration (YAML). */
export function traefikBundleUrl(ctx: Context, slug: string) {
  return `${ctx.pki_base_url}/api/pki/bundle/${slug}/traefik.yml`
}

export interface BundleCa {
  id: string
  name: string
  slug: string
  status: (typeof schema.certificateAuthorities.$inferSelect)['status']
  signing: (typeof schema.certificateAuthorities.$inferSelect)['signing']
  revoked_at: Date | null
}

/** One certificate in a bundle: a chosen CA's, or (with `include_chain`) one from its chain. */
export interface BundleCertificate {
  der: Uint8Array
  subject: string
  not_after: Date
  fingerprint_sha256: string
  /** The chosen CA this certificate belongs to or came with. */
  ca_id: string
  from_chain: boolean
}

export interface TrustBundleDetail {
  bundle: TrustBundleRow
  cas: BundleCa[]
  certificates: BundleCertificate[]
  url: string
  traefik_url: string
  /** The bundle's Traefik token in plain text, only in the answer to the call that made it. */
  traefik_token?: string
}

/** Prefix that makes the tokens recognisable, e.g. for secret scanning. */
export const TRAEFIK_TOKEN_PREFIX = 'tb_'

/** A new token and the hash that is stored for it. */
function newTraefikToken() {
  const token = `${TRAEFIK_TOKEN_PREFIX}${randomToken(32)}`
  return { token, hash: sha256(token) }
}

/** The Traefik settings of a bundle, as the create and update inputs carry them. */
export interface TraefikInput {
  traefik_enabled?: boolean
  traefik_client_auth?: boolean
  traefik_client_auth_type?: string
  traefik_tls_option_name?: string | null
  traefik_servers_transport?: boolean
  traefik_servers_transport_name?: string | null
  traefik_require_token?: boolean
}

const TRAEFIK_FIELDS = [
  'traefik_enabled',
  'traefik_client_auth',
  'traefik_client_auth_type',
  'traefik_tls_option_name',
  'traefik_servers_transport',
  'traefik_servers_transport_name',
  'traefik_require_token',
] as const

/** A blank name means "use the default", which is stored as null. */
const nameOrNull = (value: string | null | undefined) => (value === undefined ? undefined : value?.trim() || null)

/** The Traefik columns an input sets, with names normalised. Only the fields the input has. */
function traefikValues(input: TraefikInput) {
  const values: Partial<Pick<TrustBundleRow, (typeof TRAEFIK_FIELDS)[number]>> = {}
  for (const key of TRAEFIK_FIELDS) {
    if (input[key] === undefined) continue
    ;(values as Record<string, unknown>)[key] = key.endsWith('_name') ? nameOrNull(input[key] as string | null) : input[key]
  }
  return values
}

/** Check the Traefik settings a bundle will have after the change. */
function checkTraefik(next: Pick<TrustBundleRow, (typeof TRAEFIK_FIELDS)[number]>) {
  if (!(TRAEFIK_CLIENT_AUTH_TYPES as readonly string[]).includes(next.traefik_client_auth_type)) {
    throw new ValidationError('Pick a client authentication type from the list', 'invalid_traefik_client_auth_type')
  }
  const nameMessage = 'Names use letters, digits, hyphens and underscores, start with a letter or digit, and have at most 63 characters'
  if (next.traefik_tls_option_name !== null && !TRAEFIK_NAME_PATTERN.test(next.traefik_tls_option_name)) throw new ValidationError(nameMessage, 'invalid_traefik_tls_option_name')
  if (next.traefik_servers_transport_name !== null && !TRAEFIK_NAME_PATTERN.test(next.traefik_servers_transport_name)) {
    throw new ValidationError(nameMessage, 'invalid_traefik_servers_transport_name')
  }
  if (next.traefik_enabled && !next.traefik_client_auth && !next.traefik_servers_transport) {
    throw new ValidationError('Turn on client authentication or backend trust, or Traefik has nothing to get', 'traefik_target_required')
  }
}

const TRAEFIK_DEFAULTS = {
  traefik_enabled: false,
  traefik_client_auth: true,
  traefik_client_auth_type: 'RequireAndVerifyClientCert',
  traefik_tls_option_name: null,
  traefik_servers_transport: true,
  traefik_servers_transport_name: null,
  traefik_require_token: false,
} satisfies Pick<TrustBundleRow, (typeof TRAEFIK_FIELDS)[number]>

function checkInput(input: { name?: string; description?: string; ca_ids?: string[] }) {
  if (input.name !== undefined && (!input.name.trim() || input.name.trim().length > 100)) throw new ValidationError('The name must be 1 to 100 characters')
  if (input.description !== undefined && input.description.length > 1000) throw new ValidationError('The description may be at most 1000 characters')
  if (input.ca_ids !== undefined) {
    if (!input.ca_ids.length) throw new ValidationError('Pick at least one CA', 'bundle_cas_required')
    if (input.ca_ids.length > MAX_BUNDLE_CAS) throw new ValidationError(`At most ${MAX_BUNDLE_CAS} CAs per bundle`)
    if (new Set(input.ca_ids).size !== input.ca_ids.length) throw new ValidationError('A CA is listed twice')
  }
}

/** Every listed CA exists and has a certificate to publish. */
async function checkCas(db: Executor, ca_ids: string[]) {
  const cas = schema.certificateAuthorities
  const rows = await db.select({ id: cas.id, status: cas.status }).from(cas).where(inArray(cas.id, ca_ids))
  const missing = ca_ids.filter((id) => !rows.some((row) => row.id === id))
  if (missing.length) throw new NotFoundError('Certificate authority not found', 'ca_not_found')
  if (rows.some((row) => row.status === 'pending_certificate')) throw new ConflictError('A CA without a certificate cannot go into a bundle', 'ca_not_active')
}

async function setCas(tx: Executor, bundle_id: string, ca_ids: string[]) {
  await tx.delete(schema.trustBundleCas).where(eq(schema.trustBundleCas.bundle_id, bundle_id))
  await tx.insert(schema.trustBundleCas).values(ca_ids.map((ca_id, position) => ({ bundle_id, ca_id, position })))
}

async function findBundle(db: Executor, where: ReturnType<typeof eq>): Promise<TrustBundleRow> {
  const [row] = await db.select().from(schema.trustBundles).where(where)
  if (!row) throw new NotFoundError('Trust bundle not found')
  return row
}

async function bundleCas(db: Executor, bundle_id: string): Promise<BundleCa[]> {
  const cas = schema.certificateAuthorities
  return db
    .select({ id: cas.id, name: cas.name, slug: cas.slug, status: cas.status, signing: cas.signing, revoked_at: cas.revoked_at })
    .from(schema.trustBundleCas)
    .innerJoin(cas, eq(cas.id, schema.trustBundleCas.ca_id))
    .where(eq(schema.trustBundleCas.bundle_id, bundle_id))
    .orderBy(asc(schema.trustBundleCas.position))
}

/**
 * What a bundle holds: for each CA that is not revoked, in the order they were picked, the newest
 * certificate of every key that still has a valid one (the active key's first), so certificates
 * signed before a new-key renewal still verify; then, with `include_chain`, their issuers up to
 * the root. Expired certificates are left out, and each certificate appears once.
 */
export async function bundleCertificates(db: Executor, bundle: TrustBundleRow, cas: BundleCa[], now = new Date()): Promise<BundleCertificate[]> {
  const live = cas.filter((ca) => !ca.revoked_at)
  if (!live.length) return []
  const v = schema.caCertificates
  const versions = await db
    .select({ ca_id: v.ca_id, key_id: v.key_id, der: v.certificate_der, chain_pem: v.chain_pem, not_after: v.not_after, active_key_id: schema.certificateAuthorities.active_key_id })
    .from(v)
    .innerJoin(schema.certificateAuthorities, eq(schema.certificateAuthorities.id, v.ca_id))
    .where(and(inArray(v.ca_id, live.map((ca) => ca.id)), isNull(v.revoked_at)))
    .orderBy(desc(v.version))

  const seen = new Set<string>()
  const out: BundleCertificate[] = []
  const add = async (der: Uint8Array, ca_id: string, from_chain: boolean) => {
    const info = await inspectCertificate(der)
    if (seen.has(info.fingerprint_sha256) || info.not_after.getTime() <= now.getTime()) return
    seen.add(info.fingerprint_sha256)
    out.push({ der: info.der, subject: info.subject, not_after: info.not_after, fingerprint_sha256: info.fingerprint_sha256, ca_id, from_chain })
  }
  // The newest valid certificate of each key, the active key's first.
  const chosen = live.map((ca) => {
    const perKey = new Map<string, (typeof versions)[number]>()
    const mine = versions
      .filter((row) => row.ca_id === ca.id && row.not_after.getTime() > now.getTime())
      .sort((a, b) => Number(b.key_id === b.active_key_id) - Number(a.key_id === a.active_key_id))
    for (const row of mine) if (!perKey.has(row.key_id)) perKey.set(row.key_id, row)
    return { ca, rows: [...perKey.values()] }
  })
  // The chosen certificates first, then the chains, so a chosen CA never counts as chain.
  for (const { ca, rows } of chosen) for (const row of rows) await add(row.der, ca.id, false)
  if (bundle.include_chain) {
    for (const { ca, rows } of chosen) {
      for (const row of rows) for (const der of row.chain_pem.trim() ? parseCertificateBundle(row.chain_pem) : []) await add(der, ca.id, true)
    }
  }
  return out
}

async function detail(ctx: Context, bundle: TrustBundleRow): Promise<TrustBundleDetail> {
  const cas = await bundleCas(ctx.db, bundle.id)
  return { bundle, cas, certificates: await bundleCertificates(ctx.db, bundle, cas), url: trustBundleUrl(ctx, bundle.slug), traefik_url: traefikBundleUrl(ctx, bundle.slug) }
}

export interface CreateTrustBundleInput extends TraefikInput {
  name: string
  slug: string
  description?: string
  ca_ids: string[]
  include_chain?: boolean
}

/** Create a trust bundle. Admins only, from a recently re-authenticated session. */
export async function createTrustBundle(ctx: Context, actor: Actor, input: CreateTrustBundleInput): Promise<TrustBundleDetail> {
  authorize(trustBundlePolicy, actor, 'create', undefined)
  assertStepUp(actor)
  checkInput(input)
  if (!CA_SLUG_PATTERN.test(input.slug)) throw new ValidationError('The slug must be lowercase letters, digits and hyphens (at most 64)', 'invalid_slug')
  const traefik = { ...TRAEFIK_DEFAULTS, ...traefikValues(input) }
  checkTraefik(traefik)
  const issued = traefik.traefik_require_token ? newTraefikToken() : null
  try {
    const bundle = await withTransaction(ctx, async (tx) => {
      await checkCas(tx, input.ca_ids)
      const [row] = await tx
        .insert(schema.trustBundles)
        .values({ name: input.name.trim(), slug: input.slug, description: input.description?.trim() ?? '', include_chain: input.include_chain ?? false, ...traefik, traefik_token_hash: issued?.hash ?? null })
        .returning()
      await setCas(tx, row!.id, input.ca_ids)
      await recordEvent(ctx, eventFor(actor, 'trust_bundles.create', subjectOf(row!.id), { slug: row!.slug, ca_ids: input.ca_ids, include_chain: row!.include_chain, traefik_enabled: row!.traefik_enabled, traefik_token_issued: !!issued }), tx)
      return row!
    })
    return { ...(await detail(ctx, bundle)), ...(issued ? { traefik_token: issued.token } : {}) }
  } catch (error) {
    if (isUniqueViolation(error, 'trust_bundles_slug_unique')) throw new ConflictError('Another trust bundle already uses this slug', 'slug_taken')
    throw error
  }
}

export interface UpdateTrustBundleInput extends TraefikInput {
  name?: string
  description?: string
  ca_ids?: string[]
  include_chain?: boolean
}

/** Change a trust bundle; its slug, and so its public URL, stays. Admins only, with step-up. */
export async function updateTrustBundle(ctx: Context, actor: Actor, id: string, input: UpdateTrustBundleInput): Promise<TrustBundleDetail> {
  authorize(trustBundlePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  checkInput(input)
  const bundle = await withTransaction(ctx, async (tx) => {
    const current = await findBundle(tx, eq(schema.trustBundles.id, id))
    const traefik = traefikValues(input)
    const next = { ...current, ...traefik }
    checkTraefik(next)
    // A token exists exactly while one is required: made when the requirement is turned on, dropped when it is turned off.
    const issued = next.traefik_require_token && !current.traefik_token_hash ? newTraefikToken() : null
    const tokenHash = next.traefik_require_token ? (issued?.hash ?? current.traefik_token_hash) : null
    if (input.ca_ids) {
      await checkCas(tx, input.ca_ids)
      await setCas(tx, id, input.ca_ids)
    }
    const [row] = await tx
      .update(schema.trustBundles)
      .set({
        ...(input.name !== undefined ? { name: input.name.trim() } : {}),
        ...(input.description !== undefined ? { description: input.description.trim() } : {}),
        ...(input.include_chain !== undefined ? { include_chain: input.include_chain } : {}),
        ...traefik,
        traefik_token_hash: tokenHash,
        // The public file changes with the CAs too; caches go by this.
        updated_at: new Date(),
      })
      .where(eq(schema.trustBundles.id, id))
      .returning()
    const changed = Object.keys(input).filter((key) => input[key as keyof UpdateTrustBundleInput] !== undefined)
    await recordEvent(
      ctx,
      eventFor(actor, 'trust_bundles.update', subjectOf(id), { changed, ...(input.ca_ids ? { ca_ids: input.ca_ids } : {}), ...(issued ? { traefik_token_issued: true } : {}) }),
      tx,
    )
    return { bundle: row!, issued }
  })
  return { ...(await detail(ctx, bundle.bundle)), ...(bundle.issued ? { traefik_token: bundle.issued.token } : {}) }
}

/**
 * Replace a bundle's Traefik token; the old one stops working at once and the new one is returned
 * once, in `traefik_token`. Only for bundles that require a token. Admins only, with step-up.
 */
export async function regenerateTraefikToken(ctx: Context, actor: Actor, id: string): Promise<TrustBundleDetail> {
  authorize(trustBundlePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  const issued = newTraefikToken()
  const bundle = await withTransaction(ctx, async (tx) => {
    const current = await findBundle(tx, eq(schema.trustBundles.id, id))
    if (!current.traefik_require_token) throw new ConflictError('This bundle does not require a token', 'traefik_token_not_required')
    const [row] = await tx.update(schema.trustBundles).set({ traefik_token_hash: issued.hash, updated_at: new Date() }).where(eq(schema.trustBundles.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'trust_bundles.regenerate_traefik_token', subjectOf(id), { slug: current.slug }), tx)
    return row!
  })
  return { ...(await detail(ctx, bundle)), traefik_token: issued.token }
}

/** Delete a trust bundle; its public URL stops working. Admins only, with step-up. */
export async function deleteTrustBundle(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(trustBundlePolicy, actor, 'delete', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const bundle = await findBundle(tx, eq(schema.trustBundles.id, id))
    await tx.delete(schema.trustBundles).where(eq(schema.trustBundles.id, id))
    await recordEvent(ctx, eventFor(actor, 'trust_bundles.delete', subjectOf(id), { slug: bundle.slug }), tx)
  })
}

/** Trust bundles, alphabetically, each with its CAs. Every role may read. */
export async function listTrustBundles(ctx: Context, actor: Actor, input: CursorInput) {
  authorize(trustBundlePolicy, actor, 'read', undefined)
  const b = schema.trustBundles
  const page = keyset(byName(b.name, b.id), input)
  const rows = await ctx.db.select({ cursor_keys: page.keys, bundle: b }).from(b).where(page.where).orderBy(...page.orderBy).limit(page.limit)
  const { rows: kept, next_cursor } = paged(rows, input.limit)
  const data = await Promise.all(kept.map(async ({ bundle }) => ({ bundle, cas: await bundleCas(ctx.db, bundle.id), url: trustBundleUrl(ctx, bundle.slug), traefik_url: traefikBundleUrl(ctx, bundle.slug) })))
  return { rows: data, next_cursor }
}

/** One trust bundle with its CAs and the certificates its PEM holds right now. */
export async function getTrustBundle(ctx: Context, actor: Actor, id: string): Promise<TrustBundleDetail> {
  authorize(trustBundlePolicy, actor, 'read', undefined)
  return detail(ctx, await findBundle(ctx.db, eq(schema.trustBundles.id, id)))
}

/** A bundle's PEM by slug, for the public endpoint (no actor). Null when there is no such bundle. */
export async function publicTrustBundle(ctx: Context, slug: string) {
  const [bundle] = await ctx.db.select().from(schema.trustBundles).where(eq(schema.trustBundles.slug, slug))
  if (!bundle) return null
  const certificates = await bundleCertificates(ctx.db, bundle, await bundleCas(ctx.db, bundle.id))
  return { pem: certificates.map((cert) => certificateToPem(cert.der)).join(''), updated_at: bundle.updated_at }
}

/**
 * A bundle's Traefik dynamic configuration by slug, for the public endpoint. Null when there is
 * no such bundle or Traefik is off for it, so a disabled bundle looks like a missing one. When the
 * bundle requires a token, `token` is the bearer token the caller sent: none gives 401, one that
 * is not this bundle's gives 403.
 */
export async function publicTraefikConfig(ctx: Context, slug: string, token: string | null) {
  const [bundle] = await ctx.db.select().from(schema.trustBundles).where(eq(schema.trustBundles.slug, slug))
  if (!bundle?.traefik_enabled) return null
  if (bundle.traefik_require_token) {
    if (!token) throw new AuthenticationError('A token is required', 'traefik_token_required')
    if (!bundle.traefik_token_hash || !safeEqualHex(sha256(token), bundle.traefik_token_hash)) throw new AuthorizationError('This token does not open this bundle', 'traefik_token_invalid')
  }
  const certificates = await bundleCertificates(ctx.db, bundle, await bundleCas(ctx.db, bundle.id))
  // Traefik keeps what it had when a poll fails, which beats handing it a trust list with nothing in it.
  if (!certificates.length) throw new AppError(503, 'no_certificates', 'The bundle has no valid certificates right now')
  return {
    config: traefikConfig(bundle, certificates.map((cert) => certificateToPem(cert.der))),
    updated_at: bundle.updated_at,
  }
}
