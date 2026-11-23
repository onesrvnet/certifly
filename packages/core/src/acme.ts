import { type Executor, schema } from '@certifly/db'
import {
  certificateToPem,
  decodeBase64Url,
  fingerprint,
  inspectCertificate,
  isValidEmail,
  JWS_ALGORITHMS,
  jwkSpki,
  jwkThumbprint,
  jwsPayloadObject,
  JwsError,
  keyAuthorization,
  normalizeJwk,
  normalizeSan,
  parseCsr,
  parseJws,
  type ParsedJws,
  PkiError,
  type PublicJwk,
  revocationReasonName,
  type San,
  verifyHmacJws,
  verifyJws,
} from '@certifly/pki'
import { and, asc, count, desc, eq, inArray, lt, sql } from 'drizzle-orm'
import { validateHttp01, validateTlsAlpn01 } from './acme-validation'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import { issueCertificateAs, type ProtocolRequester, requestEvent, sanViolations } from './certificates'
import type { Context } from './context'
import { decryptSecret, encryptSecret, randomToken } from './crypto'
import { AppError, ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, templatePolicy } from './policies'
import { LEAF_REVOCATION_REASONS, revokeCertificateAs } from './revocation'
import type { TemplateRow } from './templates'

/*
 * ACME (RFC 8555) per template, with external account binding required, and the http-01 and
 * tls-alpn-01 challenges (RFC 8737; IP identifiers per RFC 8738). The server layer reads and
 * writes HTTP; everything decided here: who may do what, what an order may contain, and what
 * gets issued. Certificates come out of the same pipeline as every other request.
 */

export type AcmeEabKeyRow = typeof schema.acmeEabKeys.$inferSelect
export type AcmeAccountRow = typeof schema.acmeAccounts.$inferSelect
type AcmeOrderRow = typeof schema.acmeOrders.$inferSelect
type AcmeAuthorizationRow = typeof schema.acmeAuthorizations.$inferSelect
type AcmeChallengeRow = typeof schema.acmeChallenges.$inferSelect
type AcmeIdentifier = AcmeOrderRow['identifiers'][number]

const MINUTE_MS = 60 * 1000
const DAY_MS = 24 * 60 * MINUTE_MS
/** A nonce is used within moments; a client that waits longer simply gets a `badNonce` and retries. */
export const NONCE_TTL_MS = 30 * MINUTE_MS
/** How long an order and its authorizations stay open. */
export const ORDER_TTL_MS = 7 * DAY_MS
const MAX_IDENTIFIERS = 100
const MAX_OPEN_ORDERS = 200
const MAX_CONTACTS = 5
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const CHALLENGE_TYPES = ['http-01', 'tls-alpn-01'] as const
const identifierKey = (identifier: { type: string; value: string }) => `${identifier.type}:${identifier.value}`

// ---------------------------------------------------------------------------------------------
// Errors

export type AcmeErrorType =
  | 'accountDoesNotExist'
  | 'alreadyRevoked'
  | 'badCSR'
  | 'badNonce'
  | 'badPublicKey'
  | 'badRevocationReason'
  | 'badSignatureAlgorithm'
  | 'externalAccountRequired'
  | 'invalidContact'
  | 'malformed'
  | 'orderNotReady'
  | 'rateLimited'
  | 'rejectedIdentifier'
  | 'serverInternal'
  | 'unauthorized'
  | 'unsupportedContact'
  | 'unsupportedIdentifier'

/** An ACME protocol error; `type` is the end of its `urn:ietf:params:acme:error:` type. */
export class AcmeError extends AppError {
  constructor(
    status: number,
    readonly type: AcmeErrorType,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(status, type, message, details)
  }
}

export const acmeErrorUrn = (type: string) => `urn:ietf:params:acme:error:${type}`

/** The RFC 7807 problem document for an error, and the HTTP status to send it with. */
export function acmeProblem(error: unknown): { status: number; body: Record<string, unknown> } {
  if (error instanceof AcmeError) return { status: error.status, body: { type: acmeErrorUrn(error.type), detail: error.message, status: error.status, ...error.details } }
  if (error instanceof AppError) {
    const type: AcmeErrorType = error.status < 500 ? 'malformed' : 'serverInternal'
    return { status: error.status, body: { type: acmeErrorUrn(type), detail: error.message, status: error.status } }
  }
  return { status: 500, body: { type: acmeErrorUrn('serverInternal'), detail: 'Something went wrong', status: 500 } }
}

function jwsFailure(error: unknown): never {
  if (error instanceof JwsError) {
    if (error.kind === 'bad_algorithm') throw new AcmeError(400, 'badSignatureAlgorithm', error.message, { algorithms: [...JWS_ALGORITHMS] })
    if (error.kind === 'bad_public_key') throw new AcmeError(400, 'badPublicKey', error.message)
    throw new AcmeError(400, 'malformed', error.message)
  }
  throw error
}

// ---------------------------------------------------------------------------------------------
// URLs

const baseUrl = (ctx: Context, slug: string) => `${ctx.pki_base_url}/acme/${slug}`
const accountUrl = (ctx: Context, slug: string, id: string) => `${baseUrl(ctx, slug)}/account/${id}`
const orderUrl = (ctx: Context, slug: string, id: string) => `${baseUrl(ctx, slug)}/order/${id}`
const finalizeUrl = (ctx: Context, slug: string, id: string) => `${baseUrl(ctx, slug)}/order/${id}/finalize`
const authzUrl = (ctx: Context, slug: string, id: string) => `${baseUrl(ctx, slug)}/authz/${id}`
const challengeUrl = (ctx: Context, slug: string, id: string) => `${baseUrl(ctx, slug)}/challenge/${id}`
const certificateUrl = (ctx: Context, slug: string, id: string) => `${baseUrl(ctx, slug)}/cert/${id}`

// ---------------------------------------------------------------------------------------------
// Template and nonces

/** The template behind `/acme/<slug>/`; 404 unless it is active and allows ACME. */
export async function findAcmeTemplate(ctx: Context, slug: string): Promise<TemplateRow> {
  const t = schema.templates
  const [template] = await ctx.db.select().from(t).where(and(eq(t.slug, slug), eq(t.status, 'active'), eq(t.allow_acme, true)))
  if (!template) throw new AcmeError(404, 'malformed', 'There is no ACME directory here')
  return template
}

/** A fresh replay nonce (RFC 8555 §6.5). Each is accepted once. */
export async function issueAcmeNonce(ctx: Context): Promise<string> {
  const nonce = randomToken(16)
  await ctx.db.insert(schema.acmeNonces).values({ nonce, expires_at: new Date(Date.now() + NONCE_TTL_MS) })
  return nonce
}

/** Uses up a nonce: true only the first time, and only before it expires. */
async function consumeNonce(ctx: Context, nonce: string): Promise<boolean> {
  const n = schema.acmeNonces
  const rows = await ctx.db.delete(n).where(and(eq(n.nonce, nonce), sql`${n.expires_at} > now()`)).returning({ nonce: n.nonce })
  return rows.length > 0
}

/** Removes nonces that ran out without being used. Part of the cleanup job. */
export async function deleteExpiredAcmeNonces(ctx: Context, now = new Date()) {
  const rows = await ctx.db.delete(schema.acmeNonces).where(lt(schema.acmeNonces.expires_at, now)).returning({ nonce: schema.acmeNonces.nonce })
  return rows.length
}

/** Removes orders (with their authorizations and challenges) that ended long ago. Part of the cleanup job. */
export async function deleteExpiredAcmeOrders(ctx: Context, before: Date) {
  const rows = await ctx.db.delete(schema.acmeOrders).where(lt(schema.acmeOrders.expires_at, before)).returning({ id: schema.acmeOrders.id })
  return rows.length
}

/** The directory document (RFC 8555 §7.1.1). */
export async function acmeDirectory(ctx: Context, slug: string) {
  await findAcmeTemplate(ctx, slug)
  const base = baseUrl(ctx, slug)
  return {
    newNonce: `${base}/new-nonce`,
    newAccount: `${base}/new-account`,
    newOrder: `${base}/new-order`,
    revokeCert: `${base}/revoke-cert`,
    meta: { externalAccountRequired: true },
  }
}

export const acmeDirectoryLink = (ctx: Context, slug: string) => `<${baseUrl(ctx, slug)}/directory>;rel="index"`

// ---------------------------------------------------------------------------------------------
// Request verification (RFC 8555 §6)

export interface AcmeRequest {
  slug: string
  /** The request path without its query, e.g. `/acme/web/new-order`. */
  path: string
  content_type: string | undefined
  /** The parsed JSON body. */
  body: unknown
  /** The id in the URL, for resources that have one. */
  id?: string
  ip?: string | null
}

export interface AcmeResult {
  status: number
  /** A JSON document, or a string sent as is with `content_type`. */
  body?: unknown
  content_type?: string
  location?: string
  link?: string[]
}

interface Verified {
  template: TemplateRow
  jws: ParsedJws
  /** The key that signed it: the request's own `jwk`, or the account's. */
  jwk: PublicJwk
  /** Set when the request was signed with an account key (`kid`). */
  account: AcmeAccountRow | null
  /** Null for a POST-as-GET (an empty payload). */
  payload: Record<string, unknown> | null
}

/**
 * Checks the envelope of every request: JWS type and signature algorithm, `url` equal to the
 * address it was sent to, exactly one of `jwk` and `kid` (as the endpoint allows), a nonce that
 * is used up here, a key that is known, and the signature. Accounts whose key binding was
 * revoked, or that were deactivated, are refused.
 */
async function verifyRequest(ctx: Context, template: TemplateRow, req: AcmeRequest, allow: { jwk: boolean; kid: boolean }): Promise<Verified> {
  if (!/^application\/jose\+json\s*(;|$)/i.test(req.content_type ?? '')) throw new AcmeError(400, 'malformed', 'The Content-Type must be application/jose+json')
  let jws: ParsedJws
  try {
    jws = parseJws(req.body)
  } catch (error) {
    return jwsFailure(error)
  }
  const { header } = jws
  const alg = header.alg
  if (typeof alg !== 'string' || !(JWS_ALGORITHMS as readonly string[]).includes(alg)) {
    throw new AcmeError(400, 'badSignatureAlgorithm', 'Unsupported signature algorithm', { algorithms: [...JWS_ALGORITHMS] })
  }
  if (header.url !== `${ctx.pki_base_url}${req.path}`) throw new AcmeError(403, 'unauthorized', 'The "url" in the protected header does not match this request')
  const hasJwk = header.jwk !== undefined
  const hasKid = header.kid !== undefined
  if (hasJwk === hasKid) throw new AcmeError(400, 'malformed', 'The protected header needs exactly one of "jwk" and "kid"')
  if ((hasJwk && !allow.jwk) || (hasKid && !allow.kid)) throw new AcmeError(400, 'malformed', hasJwk ? 'This request must be signed with an account key ("kid")' : 'This request must carry the account key ("jwk")')
  if (typeof header.nonce !== 'string' || !header.nonce) throw new AcmeError(400, 'badNonce', 'The request has no nonce')
  if (!(await consumeNonce(ctx, header.nonce))) throw new AcmeError(400, 'badNonce', 'The nonce is unknown, expired or was used before')

  let jwk: PublicJwk
  let account: AcmeAccountRow | null = null
  try {
    if (hasJwk) jwk = normalizeJwk(header.jwk)
    else {
      account = await accountFromKid(ctx, template, header.kid)
      jwk = normalizeJwk(account.jwk)
    }
    verifyJws(jws, jwk)
  } catch (error) {
    return jwsFailure(error)
  }
  let payload: Record<string, unknown> | null = null
  if (jws.payload.length) {
    try {
      payload = jwsPayloadObject(jws)
    } catch (error) {
      return jwsFailure(error)
    }
  }
  return { template, jws, jwk, account, payload }
}

async function accountFromKid(ctx: Context, template: TemplateRow, kid: unknown): Promise<AcmeAccountRow> {
  const prefix = `${accountUrl(ctx, template.slug, '')}`
  if (typeof kid !== 'string' || !kid.startsWith(prefix) || !UUID.test(kid.slice(prefix.length))) {
    throw new AcmeError(400, 'accountDoesNotExist', 'The "kid" is not an account of this directory')
  }
  const a = schema.acmeAccounts
  const [row] = await ctx.db
    .select({ account: a, eab_revoked_at: schema.acmeEabKeys.revoked_at })
    .from(a)
    .innerJoin(schema.acmeEabKeys, eq(schema.acmeEabKeys.id, a.eab_key_id))
    .where(and(eq(a.id, kid.slice(prefix.length)), eq(a.template_id, template.id)))
  if (!row) throw new AcmeError(400, 'accountDoesNotExist', 'The account does not exist')
  if (row.account.status !== 'valid') throw new AcmeError(403, 'unauthorized', 'The account is deactivated')
  if (row.eab_revoked_at) throw new AcmeError(403, 'unauthorized', 'The external account binding key of this account was revoked')
  return row.account
}

const requester = (account: AcmeAccountRow | null, ip: string | null | undefined): ProtocolRequester => ({ kind: 'acme', id: account?.id ?? null, ip })

// ---------------------------------------------------------------------------------------------
// Accounts

const accountBody = (account: AcmeAccountRow) => ({ status: account.status, contact: account.contact })

function checkContacts(value: unknown): string[] {
  if (!Array.isArray(value)) throw new AcmeError(400, 'malformed', 'contact must be a list')
  if (value.length > MAX_CONTACTS) throw new AcmeError(400, 'invalidContact', `At most ${MAX_CONTACTS} contacts`)
  return value.map((entry) => {
    if (typeof entry !== 'string' || !entry.startsWith('mailto:')) throw new AcmeError(400, 'unsupportedContact', 'Only mailto: contacts are supported')
    const address = entry.slice('mailto:'.length)
    if (address.includes('?') || !isValidEmail(address)) throw new AcmeError(400, 'invalidContact', 'The contact is not a valid email address')
    return entry
  })
}

/**
 * The external account binding of a newAccount request (RFC 8555 §7.3.4): an HMAC-signed JWS,
 * made with the key of one of this template's EAB keys, over the account's public key.
 */
async function verifyBinding(ctx: Context, template: TemplateRow, value: unknown, jwk: PublicJwk, expectedUrl: string): Promise<AcmeEabKeyRow> {
  let jws: ParsedJws
  try {
    jws = parseJws(value)
  } catch (error) {
    return jwsFailure(error)
  }
  const { header } = jws
  if (header.url !== expectedUrl) throw new AcmeError(400, 'malformed', 'The "url" of the external account binding must be the newAccount URL')
  if ('nonce' in header || 'jwk' in header) throw new AcmeError(400, 'malformed', 'The external account binding has no nonce and no jwk')
  if (typeof header.kid !== 'string' || !header.kid) throw new AcmeError(400, 'malformed', 'The external account binding needs a "kid"')
  const k = schema.acmeEabKeys
  const [key] = await ctx.db.select().from(k).where(and(eq(k.kid, header.kid), eq(k.template_id, template.id)))
  if (!key || key.revoked_at) throw new AcmeError(403, 'unauthorized', 'The external account binding key is unknown or revoked')
  try {
    verifyHmacJws(jws, Buffer.from(decryptSecret(ctx.secret_key, key.hmac_key_encrypted), 'base64url'))
    if (jwkThumbprint(normalizeJwk(jwsPayloadObject(jws))) !== jwkThumbprint(jwk)) throw new AcmeError(400, 'malformed', 'The external account binding is for another account key')
  } catch (error) {
    if (error instanceof AcmeError) throw error
    if (error instanceof JwsError && error.kind === 'bad_signature') throw new AcmeError(403, 'unauthorized', 'The external account binding does not verify')
    return jwsFailure(error)
  }
  return key
}

async function newAccount(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: true, kid: false })
  if (!v.payload) throw new AcmeError(400, 'malformed', 'newAccount needs a payload')
  const thumbprint = jwkThumbprint(v.jwk)
  const a = schema.acmeAccounts
  const find = async (db: Executor) => (await db.select().from(a).where(and(eq(a.template_id, template.id), eq(a.jwk_thumbprint, thumbprint))).orderBy(asc(a.created_at)).limit(1))[0]
  const existing = await find(ctx.db)
  const respondExisting = (account: AcmeAccountRow): AcmeResult => {
    if (account.status !== 'valid') throw new AcmeError(403, 'unauthorized', 'The account is deactivated')
    return { status: 200, body: accountBody(account), location: accountUrl(ctx, template.slug, account.id) }
  }

  if (v.payload.onlyReturnExisting === true) {
    if (!existing) throw new AcmeError(400, 'accountDoesNotExist', 'There is no account for this key')
    return respondExisting(existing)
  }
  if (v.payload.externalAccountBinding === undefined) throw new AcmeError(403, 'externalAccountRequired', 'This directory requires an external account binding')
  const contact = v.payload.contact === undefined ? [] : checkContacts(v.payload.contact)
  const eab = await verifyBinding(ctx, template, v.payload.externalAccountBinding, v.jwk, `${ctx.pki_base_url}${req.path}`)
  if (existing) return respondExisting(existing)

  const created = await withTransaction(ctx, async (tx) => {
    // Two first requests for one key at once must end in one account.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`acme-account:${template.id}:${thumbprint}`}))`)
    const again = await find(tx)
    if (again) return { account: again, created: false }
    const [account] = await tx.insert(a).values({ template_id: template.id, eab_key_id: eab.id, jwk_thumbprint: thumbprint, jwk: v.jwk, contact }).returning()
    await tx.update(schema.acmeEabKeys).set({ last_used_at: new Date() }).where(eq(schema.acmeEabKeys.id, eab.id))
    await recordEvent(
      ctx,
      requestEvent(requester(account!, req.ip), 'acme_accounts.create', { type: 'acme_account', id: account!.id }, { template_id: template.id, eab_key_id: eab.id, jwk_thumbprint: thumbprint }),
      tx,
    )
    return { account: account!, created: true }
  })
  if (!created.created) return respondExisting(created.account)
  return { status: 201, body: accountBody(created.account), location: accountUrl(ctx, template.slug, created.account.id) }
}

async function accountResource(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  let account = v.account!
  if (req.id !== account.id) throw new AcmeError(403, 'unauthorized', 'An account can only be read and changed by itself')
  const url = accountUrl(ctx, template.slug, account.id)
  const payload = v.payload
  if (payload?.status !== undefined && payload.status !== 'deactivated') throw new AcmeError(400, 'malformed', 'The only status an account can be set to is "deactivated"')
  const contact = payload?.contact === undefined ? undefined : checkContacts(payload.contact)
  if (payload?.status === 'deactivated') {
    account = await withTransaction(ctx, async (tx) => {
      const [row] = await tx.update(schema.acmeAccounts).set({ status: 'deactivated' }).where(eq(schema.acmeAccounts.id, account.id)).returning()
      await recordEvent(ctx, requestEvent(requester(row!, req.ip), 'acme_accounts.deactivate', { type: 'acme_account', id: account.id }, { template_id: template.id }), tx)
      return row!
    })
  } else if (contact && JSON.stringify(contact) !== JSON.stringify(account.contact)) {
    account = await withTransaction(ctx, async (tx) => {
      const [row] = await tx.update(schema.acmeAccounts).set({ contact }).where(eq(schema.acmeAccounts.id, account.id)).returning()
      await recordEvent(ctx, requestEvent(requester(row!, req.ip), 'acme_accounts.update', { type: 'acme_account', id: account.id }, { template_id: template.id }), tx)
      return row!
    })
  }
  return { status: 200, body: accountBody(account), location: url }
}

// ---------------------------------------------------------------------------------------------
// Orders and authorizations

type EffectiveOrderStatus = AcmeOrderRow['status']

/** An order that was never completed and ran out of time is invalid, whatever was stored. */
function orderStatus(order: AcmeOrderRow, now: Date): EffectiveOrderStatus {
  return (order.status === 'pending' || order.status === 'ready') && order.expires_at.getTime() <= now.getTime() ? 'invalid' : order.status
}

/** Authorizations in the order of the order's identifiers; their creation times are all the same. */
function inIdentifierOrder(order: AcmeOrderRow, authzs: AcmeAuthorizationRow[]): AcmeAuthorizationRow[] {
  const position = (authz: AcmeAuthorizationRow) => order.identifiers.findIndex((identifier) => identifierKey(identifier) === identifierKey(authz.identifier))
  return [...authzs].sort((a, b) => position(a) - position(b))
}

function authzStatus(authz: AcmeAuthorizationRow, now: Date): AcmeAuthorizationRow['status'] {
  return authz.status === 'pending' && authz.expires_at.getTime() <= now.getTime() ? 'expired' : authz.status
}

function orderBody(ctx: Context, slug: string, order: AcmeOrderRow, authzs: AcmeAuthorizationRow[], now = new Date()) {
  const status = orderStatus(order, now)
  return {
    status,
    expires: order.expires_at.toISOString(),
    identifiers: order.identifiers,
    authorizations: authzs.map((authz) => authzUrl(ctx, slug, authz.id)),
    finalize: finalizeUrl(ctx, slug, order.id),
    ...(order.certificate_id && status === 'valid' ? { certificate: certificateUrl(ctx, slug, order.certificate_id) } : {}),
    ...(order.error ? { error: order.error } : {}),
  }
}

function challengeBody(ctx: Context, slug: string, challenge: AcmeChallengeRow) {
  return {
    type: challenge.type,
    url: challengeUrl(ctx, slug, challenge.id),
    status: challenge.status,
    token: challenge.token,
    ...(challenge.validated_at ? { validated: challenge.validated_at.toISOString() } : {}),
    ...(challenge.error ? { error: challenge.error } : {}),
  }
}

/** Reads the identifiers of a new order and checks them against the template. */
function checkIdentifiers(template: TemplateRow, value: unknown): AcmeIdentifier[] {
  if (!Array.isArray(value) || value.length === 0) throw new AcmeError(400, 'malformed', 'An order needs at least one identifier')
  if (value.length > MAX_IDENTIFIERS) throw new AcmeError(400, 'malformed', `At most ${MAX_IDENTIFIERS} identifiers per order`)
  const sans: San[] = []
  const seen = new Set<string>()
  for (const entry of value as unknown[]) {
    const identifier = entry as { type?: unknown; value?: unknown } | null
    if (!identifier || typeof identifier.type !== 'string' || typeof identifier.value !== 'string') throw new AcmeError(400, 'malformed', 'Every identifier needs a type and a value')
    if (identifier.type !== 'dns' && identifier.type !== 'ip') throw new AcmeError(400, 'unsupportedIdentifier', `Identifier type "${identifier.type}" is not supported; use dns or ip`)
    if (identifier.type === 'dns' && identifier.value.startsWith('*.')) {
      throw new AcmeError(403, 'rejectedIdentifier', `${identifier.value}: wildcard names need the dns-01 challenge, which this server does not offer`, {
        subproblems: [{ type: acmeErrorUrn('rejectedIdentifier'), detail: 'Wildcard names are not available', identifier }],
      })
    }
    let san: San
    try {
      san = normalizeSan({ type: identifier.type, value: identifier.value }, { allowWildcard: false })
    } catch (error) {
      if (!(error instanceof PkiError)) throw error
      throw new AcmeError(400, 'rejectedIdentifier', error.message, { subproblems: [{ type: acmeErrorUrn('rejectedIdentifier'), detail: error.message, identifier }] })
    }
    const key = `${san.type}:${san.value}`
    if (seen.has(key)) continue
    seen.add(key)
    sans.push(san)
  }
  const violations = sanViolations(template, sans)
  if (violations.length) {
    const subproblems = violations.map((violation) => {
      const [type, ...rest] = violation.san.split(':')
      return {
        type: acmeErrorUrn('rejectedIdentifier'),
        detail: violation.reason === 'san_type_not_allowed' ? 'The template does not allow this kind of name' : 'The template does not allow this name',
        identifier: { type, value: rest.join(':') },
      }
    })
    throw new AcmeError(403, 'rejectedIdentifier', `Not allowed by the template: ${violations.map((v) => v.san.replace(':', ' ')).join(', ')}`, { subproblems })
  }
  return sans.map((san) => ({ type: san.type as 'dns' | 'ip', value: san.value }))
}

async function newOrder(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  if (!v.payload) throw new AcmeError(400, 'malformed', 'newOrder needs a payload')
  const account = v.account!
  const identifiers = checkIdentifiers(template, v.payload.identifiers)
  const o = schema.acmeOrders
  const [open] = await ctx.db
    .select({ n: count() })
    .from(o)
    .where(and(eq(o.account_id, account.id), inArray(o.status, ['pending', 'ready']), sql`${o.expires_at} > now()`))
  if ((open?.n ?? 0) >= MAX_OPEN_ORDERS) throw new AcmeError(429, 'rateLimited', 'This account has too many open orders; finish or let some expire first')

  const expires_at = new Date(Date.now() + ORDER_TTL_MS)
  const { order, authzs } = await ctx.db.transaction(async (tx) => {
    const [order] = await tx.insert(o).values({ account_id: account.id, identifiers, expires_at }).returning()
    const authzs: AcmeAuthorizationRow[] = []
    for (const identifier of identifiers) {
      const [authz] = await tx.insert(schema.acmeAuthorizations).values({ order_id: order!.id, identifier, expires_at }).returning()
      await tx.insert(schema.acmeChallenges).values(CHALLENGE_TYPES.map((type) => ({ authorization_id: authz!.id, type, token: randomToken(32) })))
      authzs.push(authz!)
    }
    return { order: order!, authzs: inIdentifierOrder(order!, authzs) }
  })
  return { status: 201, body: orderBody(ctx, template.slug, order, authzs), location: orderUrl(ctx, template.slug, order.id) }
}

/** An order still processing after this long was cut off while issuing. Issuing takes seconds. */
const STALE_PROCESSING_MS = 5 * 60 * 1000

async function loadOrder(ctx: Context, account: AcmeAccountRow, id: string | undefined) {
  if (!id || !UUID.test(id)) throw new AcmeError(404, 'malformed', 'Order not found')
  let [order] = await ctx.db.select().from(schema.acmeOrders).where(and(eq(schema.acmeOrders.id, id), eq(schema.acmeOrders.account_id, account.id)))
  if (!order) throw new AcmeError(404, 'malformed', 'Order not found')
  if (order.status === 'processing' && order.updated_at.getTime() < Date.now() - STALE_PROCESSING_MS) {
    // Finalizing was cut off (a restart mid-issue): offer the order for finalizing again.
    const [ready] = await ctx.db
      .update(schema.acmeOrders)
      .set({ status: 'ready' })
      .where(and(eq(schema.acmeOrders.id, order.id), eq(schema.acmeOrders.status, 'processing'), lt(schema.acmeOrders.updated_at, new Date(Date.now() - STALE_PROCESSING_MS))))
      .returning()
    if (ready) order = ready
  }
  const authzs = await ctx.db.select().from(schema.acmeAuthorizations).where(eq(schema.acmeAuthorizations.order_id, order.id)).orderBy(asc(schema.acmeAuthorizations.created_at), asc(schema.acmeAuthorizations.id))
  return { order, authzs: inIdentifierOrder(order, authzs) }
}

async function orderResource(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  const { order, authzs } = await loadOrder(ctx, v.account!, req.id)
  return { status: 200, body: orderBody(ctx, template.slug, order, authzs), location: orderUrl(ctx, template.slug, order.id) }
}

async function authorizationResource(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  const account = v.account!
  if (!req.id || !UUID.test(req.id)) throw new AcmeError(404, 'malformed', 'Authorization not found')
  const z = schema.acmeAuthorizations
  const [row] = await ctx.db
    .select({ authz: z })
    .from(z)
    .innerJoin(schema.acmeOrders, eq(schema.acmeOrders.id, z.order_id))
    .where(and(eq(z.id, req.id), eq(schema.acmeOrders.account_id, account.id)))
  if (!row) throw new AcmeError(404, 'malformed', 'Authorization not found')
  let authz = row.authz
  if (v.payload?.status !== undefined && v.payload.status !== 'deactivated') throw new AcmeError(400, 'malformed', 'The only status an authorization can be set to is "deactivated"')
  if (v.payload?.status === 'deactivated' && (authz.status === 'pending' || authz.status === 'valid')) {
    const [updated] = await ctx.db.update(z).set({ status: 'deactivated' }).where(eq(z.id, authz.id)).returning()
    authz = updated!
  }
  const challenges = await ctx.db.select().from(schema.acmeChallenges).where(eq(schema.acmeChallenges.authorization_id, authz.id)).orderBy(asc(schema.acmeChallenges.type))
  const status = authzStatus(authz, new Date())
  return {
    status: 200,
    body: {
      identifier: authz.identifier,
      status,
      expires: authz.expires_at.toISOString(),
      challenges: challenges.map((challenge) => challengeBody(ctx, template.slug, challenge)),
    },
  }
}

async function challengeResource(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  const account = v.account!
  if (!req.id || !UUID.test(req.id)) throw new AcmeError(404, 'malformed', 'Challenge not found')
  const c = schema.acmeChallenges
  const [row] = await ctx.db
    .select({ challenge: c, authz: schema.acmeAuthorizations, order: schema.acmeOrders })
    .from(c)
    .innerJoin(schema.acmeAuthorizations, eq(schema.acmeAuthorizations.id, c.authorization_id))
    .innerJoin(schema.acmeOrders, eq(schema.acmeOrders.id, schema.acmeAuthorizations.order_id))
    .where(and(eq(c.id, req.id), eq(schema.acmeOrders.account_id, account.id)))
  if (!row) throw new AcmeError(404, 'malformed', 'Challenge not found')
  let { challenge } = row
  const up = [`<${authzUrl(ctx, template.slug, row.authz.id)}>;rel="up"`]

  // A POST with a payload (`{}`) is the client saying it is ready; an empty one only reads.
  const now = new Date()
  if (v.payload && challenge.status === 'pending' && authzStatus(row.authz, now) === 'pending' && orderStatus(row.order, now) === 'pending') {
    const started = await ctx.db.transaction(async (tx) => {
      const siblings = await tx.select({ status: c.status }).from(c).where(eq(c.authorization_id, row.authz.id))
      if (siblings.some((s) => s.status === 'processing')) return null
      const [updated] = await tx.update(c).set({ status: 'processing' }).where(and(eq(c.id, challenge.id), eq(c.status, 'pending'))).returning()
      return updated ?? null
    })
    if (started) {
      challenge = started
      // After the commit, so the job finds the challenge processing.
      ctx.enqueue({ name: 'acme.validate_challenge', data: { challenge_id: challenge.id } })
    }
  }
  return { status: 200, body: challengeBody(ctx, template.slug, challenge), link: up }
}

// ---------------------------------------------------------------------------------------------
// Challenge validation (runs in a job)

function problemDocument(type: string, detail: string) {
  return { type: acmeErrorUrn(type), detail, status: type === 'connection' || type === 'tls' ? 400 : 403 }
}

/**
 * Validate one challenge the client has said is ready, from outside, and record the outcome:
 * a valid challenge makes its authorization valid and, once every authorization of the order is,
 * the order ready; an invalid one makes its authorization and the order invalid. Does nothing
 * for a challenge that is not processing, so a job that runs twice is harmless.
 */
export async function validateAcmeChallenge(ctx: Context, challenge_id: string): Promise<void> {
  const c = schema.acmeChallenges
  const [row] = await ctx.db
    .select({ challenge: c, authz: schema.acmeAuthorizations, order: schema.acmeOrders, account: schema.acmeAccounts })
    .from(c)
    .innerJoin(schema.acmeAuthorizations, eq(schema.acmeAuthorizations.id, c.authorization_id))
    .innerJoin(schema.acmeOrders, eq(schema.acmeOrders.id, schema.acmeAuthorizations.order_id))
    .innerJoin(schema.acmeAccounts, eq(schema.acmeAccounts.id, schema.acmeOrders.account_id))
    .where(eq(c.id, challenge_id))
  if (!row || row.challenge.status !== 'processing') return

  const now = new Date()
  let failure: { type: string; detail: string } | null = null
  if (row.account.status !== 'valid') failure = { type: 'unauthorized', detail: 'The account is no longer valid' }
  else if (authzStatus(row.authz, now) !== 'pending' || orderStatus(row.order, now) !== 'pending') failure = { type: 'unauthorized', detail: 'The authorization expired or is no longer pending' }
  else {
    const identifier = row.authz.identifier
    const proof = keyAuthorization(row.challenge.token, normalizeJwk(row.account.jwk))
    const ports = { http01: ctx.acme?.http01_port ?? 80, tlsalpn01: ctx.acme?.tlsalpn01_port ?? 443 }
    failure = row.challenge.type === 'http-01' ? await validateHttp01(identifier, row.challenge.token, proof, ports.http01) : await validateTlsAlpn01(identifier, proof, ports.tlsalpn01)
  }

  await ctx.db.transaction(async (tx) => {
    // One order at a time: two authorizations finishing together must each see the other's result.
    const [order] = await tx.select().from(schema.acmeOrders).where(eq(schema.acmeOrders.id, row.order.id)).for('update')
    const [current] = await tx.select({ status: c.status }).from(c).where(eq(c.id, challenge_id))
    if (current?.status !== 'processing' || !order) return
    if (failure) {
      const error = problemDocument(failure.type, failure.detail)
      await tx.update(c).set({ status: 'invalid', error }).where(eq(c.id, challenge_id))
      await tx.update(schema.acmeAuthorizations).set({ status: 'invalid' }).where(and(eq(schema.acmeAuthorizations.id, row.authz.id), eq(schema.acmeAuthorizations.status, 'pending')))
      await tx
        .update(schema.acmeOrders)
        .set({ status: 'invalid', error: problemDocument('unauthorized', `The challenge for ${row.authz.identifier.value} failed`) })
        .where(and(eq(schema.acmeOrders.id, order.id), inArray(schema.acmeOrders.status, ['pending', 'ready'])))
      return
    }
    await tx.update(c).set({ status: 'valid', validated_at: new Date(), error: null }).where(eq(c.id, challenge_id))
    await tx.update(schema.acmeAuthorizations).set({ status: 'valid' }).where(and(eq(schema.acmeAuthorizations.id, row.authz.id), eq(schema.acmeAuthorizations.status, 'pending')))
    const authzs = await tx.select({ status: schema.acmeAuthorizations.status }).from(schema.acmeAuthorizations).where(eq(schema.acmeAuthorizations.order_id, order.id))
    if (authzs.every((authz) => authz.status === 'valid')) {
      await tx.update(schema.acmeOrders).set({ status: 'ready' }).where(and(eq(schema.acmeOrders.id, order.id), eq(schema.acmeOrders.status, 'pending')))
    }
  })
}

// ---------------------------------------------------------------------------------------------
// Finalize and certificate download

async function finalizeOrder(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  const account = v.account!
  const { order, authzs } = await loadOrder(ctx, account, req.id)
  if (typeof v.payload?.csr !== 'string') throw new AcmeError(400, 'malformed', 'finalize needs a "csr"')
  if (orderStatus(order, new Date()) !== 'ready') throw new AcmeError(403, 'orderNotReady', 'The order is not ready: every authorization must be valid first')

  // The request is checked before anything changes, so a bad CSR leaves the order ready for another try.
  let csr
  try {
    csr = await parseCsr(decodeBase64Url(v.payload.csr, 'The CSR'))
  } catch (error) {
    if (error instanceof PkiError || error instanceof JwsError) throw new AcmeError(400, 'badCSR', error.message)
    throw error
  }
  if (csr.unsupported_sans.length) throw new AcmeError(400, 'badCSR', `The CSR asks for names this server cannot issue: ${csr.unsupported_sans.join(', ')}`)
  const wanted = order.identifiers.map(identifierKey).sort()
  const asked = csr.sans.map(identifierKey).sort()
  if (JSON.stringify(wanted) !== JSON.stringify(asked)) throw new AcmeError(400, 'badCSR', "The CSR's names must be exactly the identifiers of the order")
  const cn = csr.subject_attributes.find((attribute) => attribute.type === 'CN')?.value.trim().toLowerCase()
  // A name in the subject is as good as a SAN to some clients, so it must have been validated too.
  if (cn && !order.identifiers.some((identifier) => identifier.value === cn)) throw new AcmeError(400, 'badCSR', 'The common name of the CSR must be one of the identifiers of the order')

  const o = schema.acmeOrders
  const [claimed] = await ctx.db.update(o).set({ status: 'processing' }).where(and(eq(o.id, order.id), eq(o.status, 'ready'))).returning()
  if (!claimed) throw new AcmeError(403, 'orderNotReady', 'The order is already being finalized')
  try {
    const { certificate } = await issueCertificateAs(ctx, requester(account, req.ip), {
      template_id: template.id,
      csr: csr.pem,
      sans: csr.sans,
      ...(!cn && template.require_common_name ? { common_name: order.identifiers[0]!.value } : {}),
      source: 'acme',
    })
    const [valid] = await ctx.db.update(o).set({ status: 'valid', certificate_id: certificate.id }).where(eq(o.id, order.id)).returning()
    return { status: 200, body: orderBody(ctx, template.slug, valid!, authzs), location: orderUrl(ctx, template.slug, order.id) }
  } catch (error) {
    await ctx.db.update(o).set({ status: 'ready' }).where(and(eq(o.id, order.id), eq(o.status, 'processing')))
    if (error instanceof ValidationError) throw new AcmeError(400, 'badCSR', error.message)
    if (error instanceof ConflictError || error instanceof NotFoundError) throw new AcmeError(503, 'serverInternal', error.message)
    throw error
  }
}

async function certificateResource(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: false, kid: true })
  if (!req.id || !UUID.test(req.id)) throw new AcmeError(404, 'malformed', 'Certificate not found')
  const [row] = await ctx.db
    .select({ certificate: schema.certificates, issuer_der: schema.caCertificates.certificate_der, issuer_chain: schema.caCertificates.chain_pem })
    .from(schema.acmeOrders)
    .innerJoin(schema.certificates, eq(schema.certificates.id, schema.acmeOrders.certificate_id))
    .leftJoin(schema.caCertificates, eq(schema.caCertificates.id, schema.certificates.ca_cert_id))
    .where(and(eq(schema.acmeOrders.certificate_id, req.id), eq(schema.acmeOrders.account_id, v.account!.id)))
    .limit(1)
  if (!row) throw new AcmeError(404, 'malformed', 'Certificate not found')
  const pem = certificateToPem(row.certificate.certificate_der) + (row.issuer_der ? certificateToPem(row.issuer_der) + (row.issuer_chain ?? '') : '')
  return { status: 200, body: pem, content_type: 'application/pem-certificate-chain' }
}

// ---------------------------------------------------------------------------------------------
// Revocation (RFC 8555 §7.6)

async function revokeCert(ctx: Context, template: TemplateRow, req: AcmeRequest): Promise<AcmeResult> {
  const v = await verifyRequest(ctx, template, req, { jwk: true, kid: true })
  if (typeof v.payload?.certificate !== 'string') throw new AcmeError(400, 'malformed', 'revokeCert needs a "certificate"')
  let der: Buffer
  try {
    der = decodeBase64Url(v.payload.certificate, 'The certificate')
  } catch (error) {
    return jwsFailure(error)
  }
  let reasonName: (typeof LEAF_REVOCATION_REASONS)[number] = 'unspecified'
  if (v.payload.reason !== undefined) {
    const name = typeof v.payload.reason === 'number' ? revocationReasonName(v.payload.reason) : null
    if (!name || !(LEAF_REVOCATION_REASONS as readonly string[]).includes(name)) throw new AcmeError(400, 'badRevocationReason', 'That revocation reason is not supported')
    reasonName = name as typeof reasonName
  }

  const c = schema.certificates
  const [cert] = await ctx.db.select().from(c).where(and(eq(c.fingerprint_sha256, await fingerprint(der)), eq(c.template_id, template.id)))
  if (!cert || cert.source !== 'acme') throw new AcmeError(404, 'malformed', 'This certificate was not issued by this directory')

  let allowed: boolean
  if (v.account) {
    const [order] = await ctx.db
      .select({ id: schema.acmeOrders.id })
      .from(schema.acmeOrders)
      .where(and(eq(schema.acmeOrders.account_id, v.account.id), eq(schema.acmeOrders.certificate_id, cert.id)))
      .limit(1)
    allowed = !!order
  } else {
    // Signed with the certificate's own key: possession of it is the proof (the signature was verified).
    allowed = Buffer.from((await inspectCertificate(new Uint8Array(der))).public_key_spki).equals(jwkSpki(v.jwk))
  }
  if (!allowed) throw new AcmeError(403, 'unauthorized', 'This account did not order the certificate, and the request was not signed with its key')
  if (cert.revoked_at) throw new AcmeError(400, 'alreadyRevoked', 'The certificate was already revoked')
  try {
    await revokeCertificateAs(ctx, requester(v.account, req.ip), cert.id, { reason: reasonName })
  } catch (error) {
    if (error instanceof ConflictError) throw new AcmeError(400, 'malformed', error.message)
    throw error
  }
  return { status: 200, body: '', content_type: 'application/json' }
}

// ---------------------------------------------------------------------------------------------
// Entry point

export type AcmeOperation = 'new_account' | 'new_order' | 'account' | 'order' | 'finalize' | 'authorization' | 'challenge' | 'certificate' | 'revoke_cert'

/** Handles one signed ACME POST: verifies it and does what it asks. */
export async function handleAcmePost(ctx: Context, operation: AcmeOperation, req: AcmeRequest): Promise<AcmeResult> {
  const template = await findAcmeTemplate(ctx, req.slug)
  switch (operation) {
    case 'new_account':
      return newAccount(ctx, template, req)
    case 'new_order':
      return newOrder(ctx, template, req)
    case 'account':
      return accountResource(ctx, template, req)
    case 'order':
      return orderResource(ctx, template, req)
    case 'finalize':
      return finalizeOrder(ctx, template, req)
    case 'authorization':
      return authorizationResource(ctx, template, req)
    case 'challenge':
      return challengeResource(ctx, template, req)
    case 'certificate':
      return certificateResource(ctx, template, req)
    case 'revoke_cert':
      return revokeCert(ctx, template, req)
  }
}

// ---------------------------------------------------------------------------------------------
// External account binding keys (management)

const eabSubject = (id: string) => ({ type: 'acme_eab_key', id })

async function templateById(ctx: Context, id: string): Promise<TemplateRow> {
  const [template] = await ctx.db.select().from(schema.templates).where(eq(schema.templates.id, id))
  if (!template) throw new NotFoundError('Template not found', 'template_not_found')
  return template
}

/** The binding keys of a template, newest first, revoked ones included. */
export async function listAcmeEabKeys(ctx: Context, actor: Actor, template_id: string): Promise<AcmeEabKeyRow[]> {
  authorize(templatePolicy, actor, 'read', undefined)
  await templateById(ctx, template_id)
  const k = schema.acmeEabKeys
  return ctx.db.select().from(k).where(eq(k.template_id, template_id)).orderBy(desc(k.created_at), desc(k.id))
}

/**
 * Create a binding key for a template's ACME directory. The HMAC key is generated here and
 * returned once (base64url); it is stored encrypted, because checking a binding needs the key
 * itself. Changing what can enroll is a template change: admins in an interactive session with
 * a recent re-authentication.
 */
export async function createAcmeEabKey(ctx: Context, actor: Actor, input: { template_id: string; name: string }) {
  authorize(templatePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  const name = String(input.name ?? '').trim()
  if (!name || name.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  const template = await templateById(ctx, input.template_id)
  if (template.status !== 'active') throw new ConflictError('The template is archived', 'template_archived')

  const kid = randomToken(16)
  const hmac_key = randomToken(32)
  try {
    const key = await withTransaction(ctx, async (tx) => {
      const [row] = await tx
        .insert(schema.acmeEabKeys)
        .values({ template_id: template.id, name, kid, hmac_key_encrypted: encryptSecret(ctx.secret_key, hmac_key), created_by_user_id: actor.id })
        .returning()
      await recordEvent(ctx, eventFor(actor, 'acme_eab_keys.create', eabSubject(row!.id), { template_id: template.id, name, kid }), tx)
      return row!
    })
    return { key, hmac_key }
  } catch (error) {
    if (isUniqueViolation(error)) throw new ConflictError('Try again', 'conflict')
    throw error
  }
}

/** Revoke a binding key: no new account can use it and accounts bound to it stop working at once. Revoking twice changes nothing. */
export async function revokeAcmeEabKey(ctx: Context, actor: Actor, id: string): Promise<AcmeEabKeyRow> {
  authorize(templatePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const [current] = await tx.select().from(schema.acmeEabKeys).where(eq(schema.acmeEabKeys.id, id)).for('update')
    if (!current) throw new NotFoundError('Binding key not found', 'acme_eab_key_not_found')
    if (current.revoked_at) return current
    const [row] = await tx.update(schema.acmeEabKeys).set({ revoked_at: new Date() }).where(eq(schema.acmeEabKeys.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'acme_eab_keys.revoke', eabSubject(id), { template_id: current.template_id, name: current.name, kid: current.kid }), tx)
    return row!
  })
}
