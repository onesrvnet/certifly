import { schema } from '@certifly/db'
import { buildEstCertificates, decodeEstRequestBody, dnEquals, fingerprint, parseCertificateBundle, parseCsr, parseForwardedClientCertificate, PkiError, pemEncode } from '@certifly/pki'
import { and, desc, eq, inArray } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import { type CertificateRow, issueCertificateAs, type IssueResult, type ProtocolRequester, renewCertificateAs } from './certificates'
import type { Context } from './context'
import { randomToken, safeEqualHex, sha256 } from './crypto'
import { AuthenticationError, AuthorizationError, ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, templatePolicy } from './policies'
import type { TemplateRow } from './templates'

export type EstCredentialRow = typeof schema.estCredentials.$inferSelect

const subjectOf = (id: string) => ({ type: 'est_credential', id })

/** A password hash compared when the username is unknown, so a wrong name takes as long as a wrong password. */
const UNKNOWN_USER_HASH = sha256('certifly:est:unknown-user')

async function templateById(ctx: Context, id: string): Promise<TemplateRow> {
  const [template] = await ctx.db.select().from(schema.templates).where(eq(schema.templates.id, id))
  if (!template) throw new NotFoundError('Template not found', 'template_not_found')
  return template
}

// ---------------------------------------------------------------------------------------------
// Management

/** The credentials of a template, newest first, revoked ones included. */
export async function listEstCredentials(ctx: Context, actor: Actor, template_id: string): Promise<EstCredentialRow[]> {
  authorize(templatePolicy, actor, 'read', undefined)
  await templateById(ctx, template_id)
  return ctx.db.select().from(schema.estCredentials).where(eq(schema.estCredentials.template_id, template_id)).orderBy(desc(schema.estCredentials.created_at), desc(schema.estCredentials.id))
}

/**
 * Create a named credential for a template's EST endpoints. The password is generated and
 * returned once; only its SHA-256 is stored (it carries 192 random bits, so a slow hash adds
 * nothing). Changing what can enroll is a template change: admins in an interactive session
 * with a recent re-authentication.
 */
export async function createEstCredential(ctx: Context, actor: Actor, input: { template_id: string; name: string }) {
  authorize(templatePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  const name = String(input.name ?? '').trim()
  if (!name || name.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  const template = await templateById(ctx, input.template_id)
  if (template.status !== 'active') throw new ConflictError('The template is archived', 'template_archived')

  const username = `est_${randomToken(6)}`
  const password = randomToken(24)
  try {
    const credential = await withTransaction(ctx, async (tx) => {
      const [row] = await tx
        .insert(schema.estCredentials)
        .values({ template_id: template.id, name, username, password_hash: sha256(password), created_by_user_id: actor.id })
        .returning()
      await recordEvent(ctx, eventFor(actor, 'est_credentials.create', subjectOf(row!.id), { template_id: template.id, name, username }), tx)
      return row!
    })
    return { credential, password }
  } catch (error) {
    if (isUniqueViolation(error)) throw new ConflictError('Try again', 'conflict')
    throw error
  }
}

/** Revoke a credential: it stops working at once. Revoking a revoked one changes nothing. */
export async function revokeEstCredential(ctx: Context, actor: Actor, id: string): Promise<EstCredentialRow> {
  authorize(templatePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const [current] = await tx.select().from(schema.estCredentials).where(eq(schema.estCredentials.id, id)).for('update')
    if (!current) throw new NotFoundError('EST credential not found', 'est_credential_not_found')
    if (current.revoked_at) return current
    const [row] = await tx.update(schema.estCredentials).set({ revoked_at: new Date() }).where(eq(schema.estCredentials.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'est_credentials.revoke', subjectOf(id), { template_id: current.template_id, name: current.name, username: current.username }), tx)
    return row!
  })
}

// ---------------------------------------------------------------------------------------------
// Protocol

/** The template behind `/.well-known/est/<slug>`; null (so: 404) unless it is active and allows EST. */
export async function findEstTemplate(ctx: Context, slug: string): Promise<TemplateRow | null> {
  const [template] = await ctx.db.select().from(schema.templates).where(and(eq(schema.templates.slug, slug), eq(schema.templates.status, 'active'), eq(schema.templates.allow_est, true)))
  return template ?? null
}

/** The issuing CA's certificate followed by its chain up to the root, DER (RFC 7030 §4.1). */
export async function estCaCertificates(ctx: Context, template: TemplateRow): Promise<Uint8Array[]> {
  const cas = schema.certificateAuthorities
  const [row] = await ctx.db
    .select({ cert: schema.caCertificates })
    .from(cas)
    .innerJoin(schema.caCertificates, eq(schema.caCertificates.id, cas.active_cert_id))
    .where(and(eq(cas.id, template.ca_id), inArray(cas.status, ['active', 'disabled', 'expired'])))
  if (!row) throw new NotFoundError('The CA has no certificate', 'ca_not_active')
  return [row.cert.certificate_der, ...(row.cert.chain_pem.trim() ? parseCertificateBundle(row.cert.chain_pem) : [])]
}

/**
 * The credential for HTTP basic credentials of this template, or null. The password hash is
 * compared in constant time whether or not the username exists. A credential of another
 * template or a revoked one does not authenticate. Notes the use on success.
 */
export async function authenticateEstCredential(ctx: Context, template: TemplateRow, username: string, password: string): Promise<EstCredentialRow | null> {
  const [row] = await ctx.db.select().from(schema.estCredentials).where(eq(schema.estCredentials.username, username))
  const matches = safeEqualHex(sha256(password), row?.password_hash ?? UNKNOWN_USER_HASH)
  if (!row || !matches || row.template_id !== template.id || row.revoked_at) return null
  await ctx.db.update(schema.estCredentials).set({ last_used_at: new Date() }).where(eq(schema.estCredentials.id, row.id))
  return row
}

/** Certificates as an EST answer body: a certs-only PKCS#7, base64 (RFC 7030 §4.1.3). */
export const estCertificatesBody = (certificates: readonly Uint8Array[]) => buildEstCertificates(certificates)

/** Turns a refusal from the crypto layer into a 400. */
async function pki<T>(fn: () => Promise<T> | T): Promise<T> {
  try {
    return await fn()
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code, error.details)
    throw error
  }
}

async function requestPem(body: Uint8Array) {
  const csr = await pki(async () => parseCsr(decodeEstRequestBody(body)))
  return { csr, pem: pemEncode(csr.der, 'CERTIFICATE REQUEST') }
}

/**
 * simpleenroll (RFC 7030 §4.2.1): issue with the template's rules, as for any request. The
 * credential was checked by `authenticateEstCredential`.
 */
export async function estEnroll(ctx: Context, template: TemplateRow, credential: EstCredentialRow, input: { body: Uint8Array; ip?: string | null }): Promise<IssueResult> {
  if (credential.template_id !== template.id) throw new AuthenticationError()
  const { pem } = await requestPem(input.body)
  const requester: ProtocolRequester = { kind: 'est', id: credential.id, ip: input.ip }
  return issueCertificateAs(ctx, requester, { template_id: template.id, csr: pem, source: 'est' })
}

const sanKeys = (sans: readonly { type: string; value: string }[]) => sans.map((san) => `${san.type}:${san.value}`).sort()

/** The certificate a client presents: one certifly issued with this template, still in force. */
async function presentedCertificate(ctx: Context, template: TemplateRow, header: string): Promise<CertificateRow> {
  let der: Uint8Array
  try {
    der = parseForwardedClientCertificate(header)
  } catch (error) {
    if (error instanceof PkiError) throw new AuthenticationError('The client certificate could not be read')
    throw error
  }
  const [row] = await ctx.db
    .select()
    .from(schema.certificates)
    .where(and(eq(schema.certificates.fingerprint_sha256, await fingerprint(der)), eq(schema.certificates.template_id, template.id)))
  const now = Date.now()
  if (!row || row.status !== 'active' || row.not_before.getTime() > now || row.not_after.getTime() <= now) {
    throw new AuthorizationError('The client certificate is not a current certificate of this template', 'est_certificate_not_accepted')
  }
  return row
}

/**
 * simplereenroll (RFC 7030 §4.2.2): the client proves who it is with its current certificate,
 * which the TLS proxy forwards (`client_certificate` is that header's value). The certificate
 * must be one certifly issued with this template that is valid, not revoked and not superseded,
 * and the request must carry the same subject and SANs. The result renews it: the old
 * certificate becomes superseded.
 */
export async function estReenroll(ctx: Context, template: TemplateRow, input: { client_certificate: string; body: Uint8Array; ip?: string | null }): Promise<IssueResult> {
  const current = await presentedCertificate(ctx, template, input.client_certificate)
  const { csr, pem } = await requestPem(input.body)
  const sameSubject = dnEquals(csr.subject, current.subject_dn)
  const sameSans = csr.unsupported_sans.length === 0 && JSON.stringify(sanKeys(csr.sans)) === JSON.stringify(sanKeys(current.sans))
  if (!sameSubject || !sameSans) {
    throw new ValidationError('The subject and the SANs of the request must be the same as in the certificate being renewed', 'est_request_mismatch')
  }
  const requester: ProtocolRequester = { kind: 'est', id: null, ip: input.ip }
  return renewCertificateAs(ctx, requester, current.id, { csr: pem, source: 'est' })
}
