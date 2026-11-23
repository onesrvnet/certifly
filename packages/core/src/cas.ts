import { schema, type Executor, type StoredNameConstraints, type Transaction } from '@certifly/db'
import type { KeyAlgorithm } from '@certifly/keyvault'
import {
  buildCaCsr,
  buildRootCertificate,
  certificateToPem,
  type CertificateInfo,
  type DnAttribute,
  inspectCertificate,
  type IssuedCertificate,
  isEmptyNameConstraints,
  type NameConstraintsInput,
  normalizeDn,
  normalizeNameConstraints,
  parseCertificateBundle,
  parseDn,
  PkiError,
  revocationReasonCode,
  signIntermediate,
  validateImportedCaCertificate,
} from '@certifly/pki'
import { and, desc, eq, inArray, isNull, max } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import { caSigner, generateCaKey, insertCaKey, type CaKeyRow, type NewCaKey } from './ca-keys'
import type { Context } from './context'
import { publishCrl } from './crls'
import { CA_REVOCATION_REASONS, type CaRevocationReason, checkRevocationReason } from './revocation'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, caPolicy } from './policies'

export type CaRow = typeof schema.certificateAuthorities.$inferSelect
export type CaCertificateRow = typeof schema.caCertificates.$inferSelect
export type CaCsrRow = typeof schema.caCsrs.$inferSelect
export type CaSigning = CaRow['signing']
export type CaStatus = CaRow['status']

const DAY_MS = 24 * 60 * 60 * 1000
export const DEFAULT_KEY_ALGORITHM: KeyAlgorithm = 'ecdsa-p384'
/** A week of validity, rebuilt two days before it runs out, leaves room for a cron outage. */
export const DEFAULT_CRL_VALIDITY_HOURS = 168
export const DEFAULT_CRL_OVERLAP_HOURS = 48
/** Lowercase words joined by hyphens; it ends up in public URLs that never change. */
export const CA_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/

const SUBJECT = 'certificate_authority'
const subjectOf = (id: string) => ({ type: SUBJECT, id })

/**
 * The public URLs of a CA, built from `PKI_BASE_URL`: the CRL and certificate of its active key,
 * and its chain. They follow the CA to a new key; certificates embed `caKeyUrls` instead.
 */
export function caPublicUrls(ctx: Context, slug: string) {
  const base = `${ctx.pki_base_url}/api/pki`
  return {
    crl: `${base}/crl/${slug}.crl`,
    certificate: `${base}/ca/${slug}.crt`,
    chain: `${base}/ca/${slug}/chain.pem`,
  }
}

/**
 * The CRL and certificate URLs of one CA key, embedded as CDP and AIA caIssuers in every
 * certificate that key signs. They name the key, so they stay right for those certificates after
 * the CA moves to a new key, and the key's own CRL keeps being published until the last of them
 * has expired.
 */
export function caKeyUrls(ctx: Context, slug: string, key_id: string) {
  const base = `${ctx.pki_base_url}/api/pki`
  return {
    crl: `${base}/crl/${slug}/${key_id}.crl`,
    certificate: `${base}/ca/${slug}/${key_id}.crt`,
  }
}

// ---------------------------------------------------------------------------------------------
// Input checks

interface CommonCreateInput {
  name: string
  slug: string
  description?: string
  subject: DnAttribute[]
  key_algorithm?: KeyAlgorithm
  /** null for unlimited. */
  path_length: number | null
  name_constraints?: NameConstraintsInput | null
  crl_validity_hours?: number
  crl_overlap_hours?: number
}

export type CreateCaInput =
  | (CommonCreateInput & { signing: 'self_signed'; validity_days: number })
  | (CommonCreateInput & { signing: 'internal'; parent_ca_id: string; validity_days: number })
  | (CommonCreateInput & { signing: 'external' })

/** Turns a refusal from the crypto layer into a 400 with the same stable code. */
async function pki<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code, error.details)
    throw error
  }
}

function checkSubject(subject: DnAttribute[]): string {
  try {
    const dn = normalizeDn(subject)
    if (!parseDn(dn).some((a) => a.type === 'CN')) throw new ValidationError('A CA needs a common name (CN)', 'invalid_dn')
    return dn
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code)
    throw error
  }
}

/** Normalised constraints, or null when there are none. Subordinate CAs must permit something. */
function checkNameConstraints(input: NameConstraintsInput | null | undefined, required: boolean): StoredNameConstraints | null {
  let normalized: StoredNameConstraints
  try {
    normalized = normalizeNameConstraints(input)
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code)
    throw error
  }
  const permits = normalized.permitted.dns.length + normalized.permitted.ip.length + normalized.permitted.email.length > 0
  if (required && !permits) {
    throw new ValidationError('An intermediate CA needs name constraints with at least one permitted DNS suffix, IP range or email domain', 'name_constraints_required')
  }
  return isEmptyNameConstraints(normalized) ? null : normalized
}

function checkValidityDays(days: number | undefined): number {
  if (days === undefined || !Number.isInteger(days) || days < 1 || days > 36_500) {
    throw new ValidationError('validity_days must be a whole number of days from 1 to 36500')
  }
  return days
}

function checkCrlHours(validity = DEFAULT_CRL_VALIDITY_HOURS, overlap = DEFAULT_CRL_OVERLAP_HOURS) {
  if (!Number.isInteger(validity) || validity < 1 || validity > 24 * 366) throw new ValidationError('crl_validity_hours must be from 1 to 8784')
  if (!Number.isInteger(overlap) || overlap < 0 || overlap >= validity) throw new ValidationError('crl_overlap_hours must be at least 0 and below crl_validity_hours')
  return { crl_validity_hours: validity, crl_overlap_hours: overlap }
}

// ---------------------------------------------------------------------------------------------
// Loading

async function findCa(db: Executor, id: string, lock = false): Promise<CaRow> {
  const query = db.select().from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.id, id))
  const [row] = lock ? await query.for('update') : await query
  if (!row) throw new NotFoundError('Certificate authority not found')
  return row
}

/** The installed certificate and key a CA signs with. */
async function signingMaterial(db: Executor, ca: CaRow): Promise<{ cert: CaCertificateRow; key: CaKeyRow }> {
  if (!ca.active_cert_id || !ca.active_key_id) throw new ConflictError('The CA has no certificate yet', 'ca_not_active')
  const [cert] = await db.select().from(schema.caCertificates).where(eq(schema.caCertificates.id, ca.active_cert_id))
  const [key] = await db.select().from(schema.caKeys).where(eq(schema.caKeys.id, ca.active_key_id))
  return { cert: cert!, key: key! }
}

/** A parent that may sign: active, with its certificate and key. */
async function loadParent(ctx: Context, parent_id: string) {
  const [parent] = await ctx.db.select().from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.id, parent_id))
  if (!parent) throw new NotFoundError('Parent certificate authority not found', 'parent_not_found')
  if (parent.status !== 'active') throw new ConflictError('The parent CA must be active to sign', 'parent_not_active')
  return { parent, ...(await signingMaterial(ctx.db, parent)) }
}

/** Re-checks inside the transaction that the parent was not disabled in the meantime. */
async function assertParentStillActive(tx: Transaction, parent_id: string) {
  const [row] = await tx
    .select({ status: schema.certificateAuthorities.status })
    .from(schema.certificateAuthorities)
    .where(eq(schema.certificateAuthorities.id, parent_id))
    .for('share')
  if (row?.status !== 'active') throw new ConflictError('The parent CA must be active to sign', 'parent_not_active')
}

async function nextVersion(tx: Transaction, ca_id: string): Promise<number> {
  const [row] = await tx.select({ version: max(schema.caCertificates.version) }).from(schema.caCertificates).where(eq(schema.caCertificates.ca_id, ca_id))
  return (row?.version ?? 0) + 1
}

/** Stores a certificate version and makes it (and its key) the CA's active one. */
async function installCertificate(
  tx: Transaction,
  ca: CaRow,
  cert: IssuedCertificate,
  values: { key_id: string; issuer_ca_id: string | null; issuer_key_id: string | null; chain_pem: string },
  extra: Partial<Pick<CaRow, 'name_constraints'>> = {},
): Promise<CaCertificateRow> {
  let row: CaCertificateRow
  try {
    ;[row] = (await tx
      .insert(schema.caCertificates)
      .values({
        ca_id: ca.id,
        key_id: values.key_id,
        issuer_ca_id: values.issuer_ca_id,
        issuer_key_id: values.issuer_key_id,
        version: await nextVersion(tx, ca.id),
        certificate_der: cert.der,
        chain_pem: values.chain_pem,
        serial: cert.serial,
        issuer_dn: cert.issuer,
        not_before: cert.not_before,
        not_after: cert.not_after,
        fingerprint_sha256: cert.fingerprint_sha256,
      })
      .returning()) as [CaCertificateRow]
  } catch (error) {
    if (isUniqueViolation(error, 'ca_certificates_fingerprint_idx')) throw new ConflictError('This certificate is already installed', 'certificate_already_installed')
    throw error
  }
  await tx
    .update(schema.certificateAuthorities)
    .set({
      status: 'active',
      active_cert_id: row.id,
      active_key_id: values.key_id,
      not_before: cert.not_before,
      not_after: cert.not_after,
      ...extra,
    })
    .where(eq(schema.certificateAuthorities.id, ca.id))
  return row
}

// ---------------------------------------------------------------------------------------------
// Create

/**
 * Create a certificate authority. A root is self-signed in one step; an internal CA is signed by
 * an active parent in certifly, with name constraints inside the parent's and the parent's CRL
 * and certificate URLs as CDP and AIA; an externally signed CA gets a key and a CSR and waits in
 * `pending_certificate` until its certificate is imported. Active CAs publish a first, empty CRL
 * right away. Admins only, from a recently re-authenticated session.
 */
export async function createCertificateAuthority(ctx: Context, actor: Actor, input: CreateCaInput): Promise<CaRow> {
  authorize(caPolicy, actor, 'create', undefined)
  assertStepUp(actor)

  const name = input.name.trim()
  if (!name || name.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  if (!CA_SLUG_PATTERN.test(input.slug)) throw new ValidationError('The slug must be lowercase letters, digits and hyphens (at most 64)', 'invalid_slug')
  const subject_dn = checkSubject(input.subject)
  const name_constraints = checkNameConstraints(input.name_constraints, input.signing !== 'self_signed')
  const algorithm = input.key_algorithm ?? DEFAULT_KEY_ALGORITHM
  // Ed25519 keys are for SSH authorities; X.509 certificates are signed with ECDSA or RSA.
  if (algorithm === 'ed25519') throw new ValidationError('Ed25519 keys are not supported for X.509 certificate authorities', 'unsupported_key')
  const crl = checkCrlHours(input.crl_validity_hours, input.crl_overlap_hours)
  const [taken] = await ctx.db.select({ id: schema.certificateAuthorities.id }).from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.slug, input.slug))
  if (taken) throw new ConflictError('Another CA already uses this slug', 'slug_taken')

  const ca_id = crypto.randomUUID()
  const base = {
    id: ca_id,
    slug: input.slug,
    name,
    description: input.description?.trim() ?? '',
    signing: input.signing,
    subject_dn,
    key_algorithm: algorithm,
    max_path_length: input.path_length,
    name_constraints,
    ...crl,
  }

  // Key generation and signing happen before the transaction: an RSA key can take a while.
  const key = await generateCaKey(ctx, ca_id, algorithm)

  if (input.signing === 'external') {
    const csr = await pki(() =>
      buildCaCsr({ signer: key.signer, public_key_spki: key.generated.public_key_spki, subject: subject_dn, path_length: input.path_length, name_constraints: name_constraints! }),
    )
    return createRow(ctx, actor, { ...base, parent_ca_id: null, status: 'pending_certificate' }, key, async (tx) => {
      const [row] = await tx
        .insert(schema.caCsrs)
        .values({ ca_id, key_id: key.key_id, csr_pem: csr.pem, requested_path_length: input.path_length, created_by_id: actor.id })
        .returning({ id: schema.caCsrs.id })
      await tx.update(schema.certificateAuthorities).set({ active_key_id: key.key_id }).where(eq(schema.certificateAuthorities.id, ca_id))
      return { csr_id: row!.id }
    })
  }

  const validity_days = checkValidityDays(input.validity_days)
  const not_after = new Date(Date.now() + validity_days * DAY_MS)

  if (input.signing === 'self_signed') {
    const cert = await pki(() =>
      buildRootCertificate({ signer: key.signer, public_key_spki: key.generated.public_key_spki, subject: subject_dn, not_after, path_length: input.path_length, name_constraints }),
    )
    return createRow(ctx, actor, { ...base, parent_ca_id: null, status: 'active' }, key, async (tx, ca) => {
      const installed = await installCertificate(tx, ca, cert, { key_id: key.key_id, issuer_ca_id: ca_id, issuer_key_id: key.key_id, chain_pem: '' })
      const published = await publishCrl(ctx, tx, ca_id)
      return { certificate_id: installed.id, crl_number: published.crl_number.toString() }
    })
  }

  const { parent, cert: parentCert, key: parentKey } = await loadParent(ctx, input.parent_ca_id)
  const urls = caKeyUrls(ctx, parent.slug, parentKey.id)
  const cert = await pki(() =>
    signIntermediate({
      issuer_certificate: parentCert.certificate_der,
      signer: caSigner(ctx, parentKey),
      public_key_spki: key.generated.public_key_spki,
      subject: subject_dn,
      not_after,
      path_length: input.path_length,
      name_constraints: name_constraints!,
      crl_urls: [urls.crl],
      ca_issuer_urls: [urls.certificate],
    }),
  )
  return createRow(ctx, actor, { ...base, parent_ca_id: parent.id, status: 'active' }, key, async (tx, ca) => {
    await assertParentStillActive(tx, parent.id)
    const chain_pem = certificateToPem(parentCert.certificate_der) + parentCert.chain_pem
    const installed = await installCertificate(tx, ca, cert, { key_id: key.key_id, issuer_ca_id: parent.id, issuer_key_id: parentKey.id, chain_pem })
    const published = await publishCrl(ctx, tx, ca_id)
    return { certificate_id: installed.id, crl_number: published.crl_number.toString(), parent_ca_id: parent.id }
  })
}

/** Inserts the CA and its key, runs `finish` in the same transaction and records the event. */
async function createRow(
  ctx: Context,
  actor: Actor,
  values: typeof schema.certificateAuthorities.$inferInsert,
  key: NewCaKey,
  finish: (tx: Transaction, ca: CaRow) => Promise<Record<string, unknown>>,
): Promise<CaRow> {
  try {
    return await withTransaction(ctx, async (tx) => {
      const [ca] = await tx.insert(schema.certificateAuthorities).values(values).returning()
      await insertCaKey(tx, ca!.id, key)
      const facts = await finish(tx, ca!)
      await recordEvent(ctx, eventFor(actor, 'certificate_authorities.create', subjectOf(ca!.id), { signing: ca!.signing, slug: ca!.slug, key_id: key.key_id, ...facts }), tx)
      return findCa(tx, ca!.id)
    })
  } catch (error) {
    if (isUniqueViolation(error, 'certificate_authorities_slug_unique')) throw new ConflictError('Another CA already uses this slug', 'slug_taken')
    throw error
  }
}

// ---------------------------------------------------------------------------------------------
// Import (externally signed CAs)

export interface ImportCaInput {
  /** The CA certificate the external root (or intermediate) signed, PEM or DER. */
  certificate: string
  /** The issuer chain up to and including the self-signed root, as PEM. */
  chain: string
}

/**
 * Install a certificate signed outside certifly for an externally signed CA. It must be for one
 * of the CA's keys (the active one, or one with a pending CSR), keep the subject and requested
 * pathLen, carry critical name constraints, be valid now and chain to a self-signed root. Every
 * problem found is returned in `details.errors`; the error code is the first one's. A re-import
 * later (the root operator renewed it) adds a new version and keeps the old ones. Activates the
 * CA and publishes its CRL.
 */
export async function importCaCertificate(ctx: Context, actor: Actor, id: string, input: ImportCaInput): Promise<CaRow> {
  authorize(caPolicy, actor, 'import', undefined)
  assertStepUp(actor)
  const ca = await findCa(ctx.db, id)
  if (ca.signing !== 'external') throw new ConflictError('Only externally signed CAs take an imported certificate', 'not_externally_signed')
  if (ca.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')

  // Requests still waiting, newest first; their keys and the active key may receive the certificate.
  const pending = await ctx.db
    .select()
    .from(schema.caCsrs)
    .where(and(eq(schema.caCsrs.ca_id, ca.id), isNull(schema.caCsrs.consumed_at)))
    .orderBy(desc(schema.caCsrs.created_at))
  const keyIds = [...new Set([...pending.map((csr) => csr.key_id), ...(ca.active_key_id ? [ca.active_key_id] : [])])]
  const keys = keyIds.length ? await ctx.db.select().from(schema.caKeys).where(inArray(schema.caKeys.id, keyIds)) : []
  if (!keys.length) throw new ConflictError('The CA has no key waiting for a certificate', 'ca_not_active')

  let info: CertificateInfo | null = null
  try {
    info = await inspectCertificate(input.certificate.trim())
  } catch {
    info = null
  }
  const sameKey = (key: CaKeyRow) => !!info && bytesEqual(key.public_key_spki, info.public_key_spki)
  const key = keys.find(sameKey) ?? keys.find((k) => k.id === pending[0]?.key_id) ?? keys[0]!
  const csr = pending.find((c) => c.key_id === key.id)
  const path_length = csr ? csr.requested_path_length : ca.max_path_length

  const result = await validateImportedCaCertificate(input.certificate.trim(), input.chain, {
    public_key_spki: key.public_key_spki,
    path_length,
    subject: ca.subject_dn,
  })
  if (!result.ok || !info) {
    const errors = result.errors.length ? result.errors : [{ code: 'invalid_certificate' as const, message: 'The certificate could not be parsed' }]
    throw new ValidationError(errors.map((e) => e.message).join('; '), errors[0]!.code, { errors })
  }
  const parsed = info

  return withTransaction(ctx, async (tx) => {
    const locked = await findCa(tx, ca.id, true)
    if (locked.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')
    const name_constraints = parsed.name_constraints ? { permitted: parsed.name_constraints.permitted, excluded: parsed.name_constraints.excluded } : locked.name_constraints
    // Versions are ordered: the newest may not be older than the one before it, or a stale
    // certificate kept somewhere would replace the current one.
    const [newest] = await tx
      .select({ version: schema.caCertificates.version, not_before: schema.caCertificates.not_before })
      .from(schema.caCertificates)
      .where(eq(schema.caCertificates.ca_id, ca.id))
      .orderBy(desc(schema.caCertificates.version))
      .limit(1)
    if (newest && parsed.not_before.getTime() < newest.not_before.getTime()) {
      throw new ConflictError(`The certificate is older than version ${newest.version}, the CA's newest`, 'certificate_older_than_current', {
        current_version: newest.version,
        current_not_before: newest.not_before.toISOString(),
      })
    }
    const installed = await installCertificate(tx, locked, parsed, { key_id: key.id, issuer_ca_id: null, issuer_key_id: null, chain_pem: result.chain_pem }, { name_constraints })
    await tx
      .update(schema.caCsrs)
      .set({ consumed_at: new Date() })
      .where(and(eq(schema.caCsrs.ca_id, ca.id), eq(schema.caCsrs.key_id, key.id), isNull(schema.caCsrs.consumed_at)))
    const published = await publishCrl(ctx, tx, ca.id)
    await recordEvent(
      ctx,
      eventFor(actor, 'certificate_authorities.import', subjectOf(ca.id), {
        certificate_id: installed.id,
        version: installed.version,
        key_id: key.id,
        fingerprint_sha256: installed.fingerprint_sha256,
        crl_number: published.crl_number.toString(),
      }),
      tx,
    )
    return findCa(tx, ca.id)
  })
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.byteLength === b.byteLength && a.every((v, i) => v === b[i])
}

// ---------------------------------------------------------------------------------------------
// Renew

export interface RenewCaInput {
  /** Validity of the new certificate; required for roots and internal CAs. */
  validity_days?: number
}

/**
 * Renew a CA. A root or internal CA gets a new certificate version for the same key (so the
 * certificates it issued stay valid), with the same subject, pathLen and name constraints; an
 * internal one is signed again by its parent, which must be active. An externally signed CA
 * gets a new key and a fresh CSR instead; its certificate arrives later through an import.
 * The CRL is published again under the new certificate.
 */
export async function renewCertificateAuthority(ctx: Context, actor: Actor, id: string, input: RenewCaInput): Promise<CaRow> {
  authorize(caPolicy, actor, 'renew', undefined)
  assertStepUp(actor)
  const ca = await findCa(ctx.db, id)
  if (ca.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')

  if (ca.signing === 'external') {
    const key = await generateCaKey(ctx, ca.id, ca.key_algorithm as KeyAlgorithm)
    const csr = await pki(() =>
      buildCaCsr({
        signer: key.signer,
        public_key_spki: key.generated.public_key_spki,
        subject: ca.subject_dn,
        path_length: ca.max_path_length,
        name_constraints: ca.name_constraints!,
      }),
    )
    return withTransaction(ctx, async (tx) => {
      const locked = await findCa(tx, ca.id, true)
      if (locked.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')
      await insertCaKey(tx, ca.id, key)
      const [row] = await tx
        .insert(schema.caCsrs)
        .values({ ca_id: ca.id, key_id: key.key_id, csr_pem: csr.pem, requested_path_length: ca.max_path_length, created_by_id: actor.id })
        .returning({ id: schema.caCsrs.id })
      // Without an installed certificate there is nothing to keep signing with: the new key takes over.
      if (!locked.active_cert_id) await tx.update(schema.certificateAuthorities).set({ active_key_id: key.key_id }).where(eq(schema.certificateAuthorities.id, ca.id))
      await recordEvent(ctx, eventFor(actor, 'certificate_authorities.renew', subjectOf(ca.id), { key_id: key.key_id, csr_id: row!.id, new_key: true }), tx)
      return findCa(tx, ca.id)
    })
  }

  if (ca.status !== 'active' && ca.status !== 'expired') throw new ConflictError('The CA has no certificate to renew', 'ca_not_active')
  const validity_days = checkValidityDays(input.validity_days)
  const not_after = new Date(Date.now() + validity_days * DAY_MS)
  const { key } = await signingMaterial(ctx.db, ca)

  let cert: IssuedCertificate
  let issuer_ca_id: string
  let issuer_key_id: string
  let chain_pem = ''
  if (ca.signing === 'self_signed') {
    issuer_ca_id = ca.id
    issuer_key_id = key.id
    cert = await pki(() =>
      buildRootCertificate({
        signer: caSigner(ctx, key),
        public_key_spki: key.public_key_spki,
        subject: ca.subject_dn,
        not_after,
        path_length: ca.max_path_length,
        name_constraints: ca.name_constraints,
      }),
    )
  } else {
    const { parent, cert: parentCert, key: parentKey } = await loadParent(ctx, ca.parent_ca_id!)
    const urls = caKeyUrls(ctx, parent.slug, parentKey.id)
    issuer_ca_id = parent.id
    issuer_key_id = parentKey.id
    chain_pem = certificateToPem(parentCert.certificate_der) + parentCert.chain_pem
    cert = await pki(() =>
      signIntermediate({
        issuer_certificate: parentCert.certificate_der,
        signer: caSigner(ctx, parentKey),
        public_key_spki: key.public_key_spki,
        subject: ca.subject_dn,
        not_after,
        path_length: ca.max_path_length,
        name_constraints: ca.name_constraints!,
        crl_urls: [urls.crl],
        ca_issuer_urls: [urls.certificate],
      }),
    )
  }

  return withTransaction(ctx, async (tx) => {
    const locked = await findCa(tx, ca.id, true)
    if (locked.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')
    if (ca.signing === 'internal') await assertParentStillActive(tx, issuer_ca_id)
    const installed = await installCertificate(tx, locked, cert, { key_id: key.id, issuer_ca_id, issuer_key_id, chain_pem })
    const published = await publishCrl(ctx, tx, ca.id)
    await recordEvent(
      ctx,
      eventFor(actor, 'certificate_authorities.renew', subjectOf(ca.id), {
        certificate_id: installed.id,
        version: installed.version,
        key_id: key.id,
        new_key: false,
        crl_number: published.crl_number.toString(),
      }),
      tx,
    )
    return findCa(tx, ca.id)
  })
}

// ---------------------------------------------------------------------------------------------
// Disable

/**
 * Disable a CA: it signs nothing new any more (no certificates, no subordinate CAs, no renewal),
 * but its CRL keeps being published so relying parties can still check what it issued.
 * Disabling a disabled CA changes nothing.
 */
export async function disableCertificateAuthority(ctx: Context, actor: Actor, id: string): Promise<CaRow> {
  authorize(caPolicy, actor, 'disable', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const ca = await findCa(tx, id, true)
    if (ca.status === 'disabled') return ca
    const [row] = await tx
      .update(schema.certificateAuthorities)
      .set({ status: 'disabled', disabled_at: new Date() })
      .where(eq(schema.certificateAuthorities.id, id))
      .returning()
    await recordEvent(ctx, eventFor(actor, 'certificate_authorities.disable', subjectOf(id), { previous_status: ca.status }), tx)
    return row!
  })
}

// ---------------------------------------------------------------------------------------------
// Revoke

export interface RevokeCaInput {
  reason: CaRevocationReason
}

/**
 * Revoke a CA. For an internal CA, every certificate its parent gave it goes on the parent's CRL,
 * which a job rebuilds right away, and the CA is disabled. An externally signed CA's issuer is
 * outside certifly, so it is marked compromised instead: disabled, with the reason kept, and
 * the admin revokes it at the outside issuer. A root has nobody above it to revoke it; disable it
 * instead. Revoking a revoked CA changes nothing. Admins only, from a recently re-authenticated
 * session.
 */
export async function revokeCertificateAuthority(ctx: Context, actor: Actor, id: string, input: RevokeCaInput): Promise<CaRow> {
  authorize(caPolicy, actor, 'revoke', undefined)
  assertStepUp(actor)
  const reason = checkRevocationReason(CA_REVOCATION_REASONS, input.reason)
  const result = await withTransaction(ctx, async (tx) => {
    const ca = await findCa(tx, id, true)
    if (ca.revoked_at) return { ca, rebuild: null }
    if (ca.signing === 'self_signed') throw new ConflictError('A root CA has no issuer that could revoke it; disable it instead', 'ca_not_revocable')
    const now = new Date()
    const code = revocationReasonCode(reason)
    let certificate_ids: string[] = []
    if (ca.signing === 'internal') {
      const v = schema.caCertificates
      const rows = await tx
        .update(v)
        .set({ revoked_at: now, revocation_reason: code })
        .where(and(eq(v.ca_id, ca.id), eq(v.issuer_ca_id, ca.parent_ca_id!), isNull(v.revoked_at)))
        .returning({ id: v.id })
      certificate_ids = rows.map((row) => row.id)
    }
    const [row] = await tx
      .update(schema.certificateAuthorities)
      .set({ status: 'disabled', disabled_at: ca.disabled_at ?? now, revoked_at: now, revocation_reason: code })
      .where(eq(schema.certificateAuthorities.id, ca.id))
      .returning()
    const internal = ca.signing === 'internal'
    await recordEvent(
      ctx,
      eventFor(actor, internal ? 'certificate_authorities.revoke' : 'certificate_authorities.mark_compromised', subjectOf(ca.id), {
        reason,
        previous_status: ca.status,
        ...(internal ? { parent_ca_id: ca.parent_ca_id, certificate_ids } : {}),
      }),
      tx,
    )
    return { ca: row!, rebuild: internal ? ca.parent_ca_id : null }
  })
  // After the commit, so the job sees the revocation.
  if (result.rebuild) ctx.enqueue({ name: 'crls.rebuild', data: { ca_id: result.rebuild } })
  return result.ca
}

// ---------------------------------------------------------------------------------------------
// Read

export interface CaListRow {
  ca: CaRow
  /** Issuer of the active certificate; for an externally signed CA, the outside CA that signed it. */
  issuer_dn: string | null
  /** Subjects of the imported chain, issuer first and root last; empty unless externally signed. */
  chain_subjects: string[]
}

/**
 * Every CA as a flat list with parent ids, alphabetically, for building the hierarchy. Pages
 * by keyset like every list.
 */
export async function listCertificateAuthorities(ctx: Context, actor: Actor, input: CursorInput) {
  authorize(caPolicy, actor, 'read', undefined)
  const cas = schema.certificateAuthorities
  const page = keyset(byName(cas.name, cas.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, ca: cas, issuer_dn: schema.caCertificates.issuer_dn, chain_pem: schema.caCertificates.chain_pem })
    .from(cas)
    .leftJoin(schema.caCertificates, eq(schema.caCertificates.id, cas.active_cert_id))
    .where(page.where)
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const { rows: kept, next_cursor } = paged(rows, input.limit)
  const data: CaListRow[] = await Promise.all(
    kept.map(async (row) => ({
      ca: row.ca,
      issuer_dn: row.issuer_dn,
      chain_subjects: row.ca.signing === 'external' && row.chain_pem ? await chainInfo(row.chain_pem).then((chain) => chain.map((c) => c.subject)) : [],
    })),
  )
  return { rows: data, next_cursor }
}

async function chainInfo(chain_pem: string): Promise<CertificateInfo[]> {
  if (!chain_pem.trim()) return []
  return Promise.all(parseCertificateBundle(chain_pem).map((der) => inspectCertificate(der)))
}

export interface CaDetail {
  ca: CaRow
  active_certificate: CertificateInfo | null
  /** Issuer first, root last. */
  chain: CertificateInfo[]
  chain_pem: string
  versions: CaCertificateRow[]
  /** The newest request still waiting for its certificate. */
  pending_csr: CaCsrRow | null
  /** The CRL of the active key. */
  crl: CaCrlSummary | null
  /** Every key's CRL, the active key's first: an old key keeps one while what it signed is valid. */
  crls: (CaCrlSummary & { key_id: string; active: boolean; url: string })[]
  parent: Pick<CaRow, 'id' | 'name' | 'slug' | 'status' | 'not_after'> | null
  /** The CAs above this one that certifly holds, root first; issuers outside certifly are in `chain`. */
  ancestors: CaPathEntry[]
  children: Pick<CaRow, 'id' | 'name' | 'slug' | 'status' | 'not_after' | 'revoked_at'>[]
  /** The CA's URLs, and those of its active key, which go into the certificates it signs. */
  urls: ReturnType<typeof caPublicUrls> & { key_crl: string | null; key_certificate: string | null }
}

export type CaPathEntry = Pick<CaRow, 'id' | 'name' | 'slug' | 'status' | 'signing' | 'subject_dn' | 'not_after' | 'revoked_at'>

/** Longest parent chain followed, a guard against a cycle that the schema should never allow. */
const MAX_HIERARCHY_DEPTH = 16

/** Walk the parents of a CA inside certifly, nearest first. */
async function ancestorsOf(db: Context['db'], ca: CaRow): Promise<CaPathEntry[]> {
  const cas = schema.certificateAuthorities
  const path: CaPathEntry[] = []
  let parentId = ca.parent_ca_id
  while (parentId && path.length < MAX_HIERARCHY_DEPTH) {
    const [parent] = await db
      .select({ id: cas.id, name: cas.name, slug: cas.slug, status: cas.status, signing: cas.signing, subject_dn: cas.subject_dn, not_after: cas.not_after, revoked_at: cas.revoked_at, parent_ca_id: cas.parent_ca_id })
      .from(cas)
      .where(eq(cas.id, parentId))
    if (!parent) break
    const { parent_ca_id, ...entry } = parent
    path.push(entry)
    parentId = parent_ca_id
  }
  return path
}

interface CaCrlSummary {
  crl_number: bigint
  this_update: Date
  next_update: Date
}

/** One CA with its decoded active certificate, versions, chain, pending CSR, CRL state and public URLs. */
export async function getCertificateAuthority(ctx: Context, actor: Actor, id: string): Promise<CaDetail> {
  authorize(caPolicy, actor, 'read', undefined)
  const ca = await findCa(ctx.db, id)
  const cas = schema.certificateAuthorities
  const summary = { id: cas.id, name: cas.name, slug: cas.slug, status: cas.status, not_after: cas.not_after, revoked_at: cas.revoked_at }
  const [versions, [csr], crlRows, parents, children] = await Promise.all([
    ctx.db.select().from(schema.caCertificates).where(eq(schema.caCertificates.ca_id, ca.id)).orderBy(desc(schema.caCertificates.version)),
    ctx.db
      .select()
      .from(schema.caCsrs)
      .where(and(eq(schema.caCsrs.ca_id, ca.id), isNull(schema.caCsrs.consumed_at)))
      .orderBy(desc(schema.caCsrs.created_at))
      .limit(1),
    ctx.db
      .select({ key_id: schema.crls.key_id, crl_number: schema.crls.crl_number, this_update: schema.crls.this_update, next_update: schema.crls.next_update })
      .from(schema.crls)
      .where(eq(schema.crls.ca_id, ca.id))
      .orderBy(desc(schema.crls.this_update)),
    ca.parent_ca_id ? ctx.db.select(summary).from(cas).where(eq(cas.id, ca.parent_ca_id)) : Promise.resolve([]),
    ctx.db.select(summary).from(cas).where(eq(cas.parent_ca_id, ca.id)).orderBy(cas.name),
  ])
  const active = versions.find((v) => v.id === ca.active_cert_id) ?? null
  const chain_pem = active?.chain_pem ?? ''
  const isActive = (key_id: string) => !!active && key_id === active.key_id
  const crls = crlRows
    .map(({ key_id, ...crl }) => ({ ...crl, key_id, active: isActive(key_id), url: caKeyUrls(ctx, ca.slug, key_id).crl }))
    .sort((a, b) => Number(b.active) - Number(a.active))
  const crl = crls.find((row) => row.active) ?? null
  const keyUrls = active ? caKeyUrls(ctx, ca.slug, active.key_id) : null
  return {
    ca,
    active_certificate: active ? await inspectCertificate(active.certificate_der) : null,
    chain: await chainInfo(chain_pem),
    chain_pem,
    versions,
    pending_csr: csr ?? null,
    crl: crl && { crl_number: crl.crl_number, this_update: crl.this_update, next_update: crl.next_update },
    crls,
    parent: parents[0] ?? null,
    ancestors: (await ancestorsOf(ctx.db, ca)).reverse(),
    children,
    urls: { ...caPublicUrls(ctx, ca.slug), key_crl: keyUrls?.crl ?? null, key_certificate: keyUrls?.certificate ?? null },
  }
}

// ---------------------------------------------------------------------------------------------
// Public material (no actor: served to anyone at the public PKI URLs)

/** CAs with an installed certificate; pending ones have nothing to publish. */
async function publishedCa(ctx: Context, slug: string) {
  const cas = schema.certificateAuthorities
  const [row] = await ctx.db
    .select({ cert: schema.caCertificates })
    .from(cas)
    .innerJoin(schema.caCertificates, eq(schema.caCertificates.id, cas.active_cert_id))
    .where(and(eq(cas.slug, slug), inArray(cas.status, ['active', 'disabled', 'expired'])))
  return row?.cert ?? null
}

/** The active certificate of a CA, DER, for AIA caIssuers. */
export async function publicCaCertificate(ctx: Context, slug: string) {
  const cert = await publishedCa(ctx, slug)
  return cert ? { der: cert.certificate_der, not_after: cert.not_after, updated_at: cert.updated_at } : null
}

/**
 * The newest certificate for one key of a CA, DER, for the key-specific AIA caIssuers URL. After
 * a new-key renewal it still names the key that signed the older certificates.
 */
export async function publicCaKeyCertificate(ctx: Context, slug: string, key_id: string) {
  const cas = schema.certificateAuthorities
  const v = schema.caCertificates
  const [row] = await ctx.db
    .select({ cert: v })
    .from(v)
    .innerJoin(cas, eq(cas.id, v.ca_id))
    .where(and(eq(cas.slug, slug), eq(v.key_id, key_id), inArray(cas.status, ['active', 'disabled', 'expired'])))
    .orderBy(desc(v.version))
    .limit(1)
  return row ? { der: row.cert.certificate_der, not_after: row.cert.not_after, updated_at: row.cert.updated_at } : null
}

/** The CA certificate followed by its chain up to the root, PEM. */
export async function publicCaChain(ctx: Context, slug: string) {
  const cert = await publishedCa(ctx, slug)
  return cert ? { pem: certificateToPem(cert.certificate_der) + cert.chain_pem, updated_at: cert.updated_at } : null
}
