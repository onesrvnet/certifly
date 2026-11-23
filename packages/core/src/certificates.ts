import { type Executor, type LeafKeyAlgorithm, schema, type SubjectField } from '@certifly/db'
import {
  buildLeafCertificate,
  buildPkcs12,
  certificateToPem,
  type CertificateInfo,
  type DnAttribute,
  type ExtendedKeyUsageName,
  generateLeafKeyPair,
  inspectCertificate,
  ipInCidr,
  isValidDnsName,
  type KeyUsageName,
  leafPrivateKeyToPem,
  matchesDomainPattern,
  normalizeDn,
  normalizeSans,
  parseCertificateBundle,
  parseCsr,
  type ParsedCsr,
  parseDn,
  PkiError,
  publicKeySpki,
  type San,
} from '@certifly/pki'
import { and, count, eq, getTableColumns, gt, ilike, isNotNull, lte, ne, or, type SQL, sql } from 'drizzle-orm'
import { eventFor, type NewEvent, recordEvent, withTransaction } from './audit'
import { caSigner } from './ca-keys'
import { caKeyUrls } from './cas'
import type { Context } from './context'
import { type CursorInput, keyset, paged, type SortKey } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, caPolicy, certificatePolicy } from './policies'
import { certificateTagsOf, checkTagIds, copyTagsToCertificate, replaceTags, type TagSummary } from './tags'
import { LEAF_KEY_ALGORITHMS, MIN_TTL_SECONDS, RSA_ONLY_KEY_USAGES, SUBJECT_FIELDS, type TemplateRow } from './templates'

export type CertificateRow = typeof schema.certificates.$inferSelect
export type StoredCertificateStatus = CertificateRow['status']
/** As shown: an active certificate past its notAfter reads as expired. */
export type CertificateStatus = StoredCertificateStatus
export type CertificateSource = CertificateRow['source']
export type IssueSource = Exclude<CertificateSource, 'import'>

/** A PKCS#12 password must resist offline guessing; the file may travel by mail or chat. */
export const MIN_PKCS12_PASSWORD_LENGTH = 12
/** RFC 5280 ub-common-name. */
const MAX_COMMON_NAME = 64
const DAY_MS = 24 * 60 * 60 * 1000
/** The order subject attributes are written in, most general first. */
const SUBJECT_ORDER: SubjectField[] = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'E']

const subjectOf = (id: string) => ({ type: 'certificate', id })

/**
 * Who asks when no signed-in person does: a client of an enrollment protocol. It has no user
 * behind it, and the template it enrolls with has already been checked by the protocol layer.
 */
export interface ProtocolRequester {
  kind: 'est' | 'acme'
  /** The credential or account that authenticated, when there is one. */
  id: string | null
  ip?: string | null
}

const isProtocolRequester = (actor: Actor | ProtocolRequester): actor is ProtocolRequester => actor.kind === 'est' || actor.kind === 'acme'

export function requestEvent(actor: Actor | ProtocolRequester, name: string, subject: { type: string; id: string }, data: Record<string, unknown>): NewEvent {
  if (!isProtocolRequester(actor)) return eventFor(actor, name, subject, data)
  return { actor_type: actor.kind, actor_id: actor.id, name, subject_type: subject.type, subject_id: subject.id, data, ip: actor.ip ?? null }
}

/**
 * The status to show: `expired` is derived from notAfter rather than written by a job, so it is
 * exact the moment a certificate runs out and nothing has to keep the column in step.
 */
export function effectiveStatus(row: Pick<CertificateRow, 'status' | 'not_after'>, now = new Date()): CertificateStatus {
  return row.status === 'active' && row.not_after.getTime() <= now.getTime() ? 'expired' : row.status
}

/** Turns a refusal from the crypto layer into a 400 with the same stable code. */
async function pki<T>(fn: () => Promise<T> | T): Promise<T> {
  try {
    return await fn()
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code, error.details)
    throw error
  }
}

// ---------------------------------------------------------------------------------------------
// Input

export interface KeygenInput {
  algorithm: LeafKeyAlgorithm
  /** `pem`: the PKCS#8 key as PEM. `pkcs12`: key and chain in a file protected by `pkcs12_password`. */
  format: 'pem' | 'pkcs12'
  pkcs12_password?: string
}

export interface IssueCertificateInput {
  template_id: string
  /** A PKCS#10 request, PEM. Its signature is verified. Exactly one of `csr` and `keygen`. */
  csr?: string
  /** certifly generates the key pair; the private key is returned once and never stored. */
  keygen?: KeygenInput
  common_name?: string
  /** When left out, the SANs of the CSR are used. */
  sans?: San[]
  /** Defaults to the template's default lifetime. */
  ttl_seconds?: number
  source: IssueSource
  /** Tags for the certificate, used as given (`[]` for none). Left out: the template's default tags. */
  tag_ids?: string[]
}

/** A private key handed out once. It exists only in this response. */
export type IssuedPrivateKey = { format: 'pem'; pem: string } | { format: 'pkcs12'; pkcs12_base64: string }

export interface IssueResult {
  certificate: CertificateRow
  /** notAfter was cut back to the issuing CA's notAfter. */
  not_after_clamped: boolean
  /** Subject attributes of the CSR that the template does not let requesters set; left out. */
  ignored_subject_fields: string[]
  /** Only for keygen requests. Never stored, logged or put in an event. */
  private_key?: IssuedPrivateKey
}

type KeySource = { kind: 'csr'; csr: ParsedCsr } | { kind: 'keygen'; keygen: KeygenInput }

interface IssuanceRequest {
  template: TemplateRow
  key: KeySource
  common_name?: string
  /** Requested subject attributes (from the CSR, or the certificate being renewed). */
  subject_attributes: DnAttribute[]
  sans: San[]
  ttl_seconds?: number
  source: IssueSource
  /** Where the new certificate's tags come from. */
  tags: TagSource
}

/** Tags are copied once, at issue; later changes to the template or old certificate do not follow. */
type TagSource = { from: 'ids'; ids: string[] } | { from: 'template' } | { from: 'certificate'; certificate_id: string }

// ---------------------------------------------------------------------------------------------
// Template rules

function checkKeyInput(template: TemplateRow, input: { csr?: string; keygen?: KeygenInput }): void {
  if (!!input.csr === !!input.keygen) throw new ValidationError('Send either a CSR or a key generation request', 'csr_or_keygen')
  if (!input.keygen) return
  const { algorithm, format, pkcs12_password } = input.keygen
  if (!template.allow_server_keygen) throw new ValidationError('This template does not let certifly generate keys; send a CSR', 'keygen_not_allowed')
  if (!LEAF_KEY_ALGORITHMS.includes(algorithm as (typeof LEAF_KEY_ALGORITHMS)[number]) || !template.key_algorithms.includes(algorithm)) {
    throw new ValidationError(`The template does not allow ${String(algorithm)} keys`, 'key_algorithm_not_allowed')
  }
  if (format === 'pkcs12') {
    if (typeof pkcs12_password !== 'string' || pkcs12_password.length < MIN_PKCS12_PASSWORD_LENGTH || pkcs12_password.length > 1024) {
      throw new ValidationError(`The PKCS#12 password must be ${MIN_PKCS12_PASSWORD_LENGTH} to 1024 characters`, 'pkcs12_password_too_short')
    }
  } else if (format === 'pem') {
    if (pkcs12_password !== undefined) throw new ValidationError('A password only applies to the PKCS#12 format', 'pkcs12_password_unexpected')
  } else throw new ValidationError('The key format must be pem or pkcs12')
}

function dnsAllowed(template: TemplateRow, name: string): boolean {
  return template.allowed_dns.some((pattern) => matchesDomainPattern(name, pattern))
}

export interface SanViolation {
  san: string
  reason: 'san_type_not_allowed' | 'wildcard_not_allowed' | 'san_not_allowed'
}

/**
 * Every SAN must be of a type the template allows and match its rules: DNS names a domain
 * pattern (wildcards only when allowed), IPs a CIDR, email domains and URI hosts (a SPIFFE trust
 * domain, say) a domain pattern.
 */
export function sanViolations(template: TemplateRow, sans: readonly San[]): SanViolation[] {
  const violations: SanViolation[] = []
  for (const san of sans) {
    const label = `${san.type}:${san.value}`
    if (!template.allowed_san_types.includes(san.type)) {
      violations.push({ san: label, reason: 'san_type_not_allowed' })
      continue
    }
    let ok: boolean
    switch (san.type) {
      case 'dns':
        if (san.value.startsWith('*.') && !template.allow_wildcards) {
          violations.push({ san: label, reason: 'wildcard_not_allowed' })
          continue
        }
        ok = dnsAllowed(template, san.value)
        break
      case 'ip':
        ok = template.allowed_ips.some((cidr) => ipInCidr(san.value, cidr))
        break
      case 'email':
        ok = dnsAllowed(template, san.value.slice(san.value.lastIndexOf('@') + 1).toLowerCase())
        break
      case 'uri': {
        let host = ''
        try {
          host = new URL(san.value).hostname.toLowerCase()
        } catch {
          host = ''
        }
        ok = isValidDnsName(host) && dnsAllowed(template, host)
        break
      }
    }
    if (!ok) violations.push({ san: label, reason: 'san_not_allowed' })
  }
  return violations
}

/**
 * The subject: attributes the template lets requesters set come from the request (an explicit
 * common name first, then the CSR); every other attribute comes from the template's defaults.
 * Requested attributes the template does not allow are left out and reported.
 */
function buildSubject(template: TemplateRow, request: { common_name?: string; attributes: DnAttribute[] }) {
  const allowed = new Set<string>(template.allowed_subject_fields)
  const taken: Partial<Record<SubjectField, string>> = {}
  const ignored: string[] = []
  for (const { type, value } of request.attributes) {
    if (allowed.has(type) && SUBJECT_FIELDS.includes(type as SubjectField) && taken[type as SubjectField] === undefined) taken[type as SubjectField] = value.trim()
    else if (!ignored.includes(type)) ignored.push(type)
  }
  if (request.common_name !== undefined) {
    if (!allowed.has('CN')) throw new ValidationError('This template does not let requests set a common name', 'subject_field_not_allowed')
    taken.CN = request.common_name.trim()
  }
  const subject: DnAttribute[] = []
  for (const field of SUBJECT_ORDER) {
    const value = taken[field] || template.subject_defaults[field]
    if (value) subject.push({ type: field, value })
  }
  const cn = subject.find((a) => a.type === 'CN')?.value ?? null
  if (template.require_common_name && !cn) throw new ValidationError('This template requires a common name', 'common_name_required')
  if (cn && cn.length > MAX_COMMON_NAME) throw new ValidationError(`The common name may be at most ${MAX_COMMON_NAME} characters`, 'invalid_dn')
  // Relying parties may read a host-like CN as a DNS name, so it must pass the DNS rules too.
  const hostLike = cn && cn.includes('.') && isValidDnsName(cn.toLowerCase(), { allowWildcard: true }) ? cn.toLowerCase() : null
  if (hostLike && ((hostLike.startsWith('*.') && !template.allow_wildcards) || !dnsAllowed(template, hostLike))) {
    throw new ValidationError(`The common name ${cn} does not match the template's domain patterns`, 'common_name_not_allowed')
  }
  return { subject, common_name: cn, ignored }
}

function checkTtl(template: TemplateRow, ttl_seconds: number | undefined): number {
  const ttl = ttl_seconds ?? template.default_ttl_seconds
  if (!Number.isInteger(ttl) || ttl < MIN_TTL_SECONDS) throw new ValidationError(`The lifetime must be at least ${MIN_TTL_SECONDS} seconds`, 'invalid_ttl')
  if (ttl > template.max_ttl_seconds) {
    throw new ValidationError(`The lifetime may be at most ${template.max_ttl_seconds} seconds`, 'ttl_exceeds_maximum', { max_ttl_seconds: template.max_ttl_seconds })
  }
  return ttl
}

// ---------------------------------------------------------------------------------------------
// Issue

async function findTemplateForIssue(db: Executor, id: string): Promise<TemplateRow> {
  const [template] = await db.select().from(schema.templates).where(eq(schema.templates.id, id))
  if (!template) throw new NotFoundError('Template not found', 'template_not_found')
  if (template.status !== 'active') throw new ConflictError('The template is archived', 'template_archived')
  return template
}

/** The CA's installed certificate and key, if it may sign right now. */
async function issuingMaterial(db: Executor, ca_id: string) {
  const [ca] = await db.select().from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.id, ca_id))
  if (!ca) throw new NotFoundError('Certificate authority not found', 'ca_not_found')
  if (ca.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')
  if (ca.status !== 'active' || !ca.active_cert_id || !ca.active_key_id) throw new ConflictError('The CA is not active', 'ca_not_active')
  const [cert] = await db.select().from(schema.caCertificates).where(eq(schema.caCertificates.id, ca.active_cert_id))
  const [key] = await db.select().from(schema.caKeys).where(eq(schema.caKeys.id, ca.active_key_id))
  return { ca, cert: cert!, key: key! }
}

/** Re-checks inside the transaction that the CA and template were not disabled or archived meanwhile. */
async function assertStillIssuing(tx: Executor, ca_id: string, template_id: string) {
  const [ca] = await tx.select({ status: schema.certificateAuthorities.status }).from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.id, ca_id)).for('share')
  if (ca?.status !== 'active') throw new ConflictError('The CA is not active', ca?.status === 'disabled' ? 'ca_disabled' : 'ca_not_active')
  const [template] = await tx.select({ status: schema.templates.status }).from(schema.templates).where(eq(schema.templates.id, template_id)).for('share')
  if (template?.status !== 'active') throw new ConflictError('The template is archived', 'template_archived')
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64')
}

/**
 * The one pipeline behind every issuance (UI, API, and later ACME and EST) and renewal: check the
 * request against the template, build and sign the certificate, store it and record the event in
 * `finish`'s transaction. A generated private key leaves this function only in the result.
 */
async function issue(
  ctx: Context,
  actor: Actor | ProtocolRequester,
  request: IssuanceRequest,
  finish: (tx: Executor, row: CertificateRow) => Promise<{ event: string; data: Record<string, unknown> }>,
): Promise<IssueResult> {
  const { template, key } = request

  if (key.kind === 'csr' && !template.key_algorithms.includes(key.csr.public_key.key_algorithm as LeafKeyAlgorithm)) {
    throw new ValidationError(`The template does not allow ${key.csr.public_key.key_algorithm} keys`, 'key_algorithm_not_allowed')
  }
  const sans = await pki(() => normalizeSans(request.sans))
  const violations = sanViolations(template, sans)
  if (violations.length) {
    throw new ValidationError(`Not allowed by the template: ${violations.map((v) => v.san).join(', ')}`, violations[0]!.reason, { violations })
  }
  if (template.require_san && sans.length === 0) throw new ValidationError('This template requires at least one SAN', 'san_required')
  const subject = buildSubject(template, { common_name: request.common_name, attributes: request.subject_attributes })
  const subject_dn = await pki(() => normalizeDn(subject.subject))
  if (!subject_dn && sans.length === 0) throw new ValidationError('A certificate needs a common name or at least one SAN', 'san_required')
  const ttl = checkTtl(template, request.ttl_seconds)

  const { ca, cert: caCert, key: caKey } = await issuingMaterial(ctx.db, template.ca_id)
  const key_algorithm = key.kind === 'csr' ? key.csr.public_key.key_algorithm : key.keygen.algorithm
  const isRsa = key_algorithm.startsWith('rsa')
  const key_usages = template.key_usages.filter((u) => isRsa || !RSA_ONLY_KEY_USAGES.includes(u))

  // Only now, with the request known to be acceptable: an RSA key can take a moment.
  let keyPair: CryptoKeyPair | null = key.kind === 'keygen' ? await pki(() => generateLeafKeyPair(key.keygen.algorithm)) : null
  const public_key_spki = key.kind === 'csr' ? key.csr.public_key.spki : await publicKeySpki(keyPair!.publicKey)

  // URLs of the signing key, so they stay right after the CA moves to a new key.
  const urls = caKeyUrls(ctx, ca.slug, caKey.id)
  const built = await pki(() =>
    buildLeafCertificate({
      issuer_certificate: caCert.certificate_der,
      signer: caSigner(ctx, caKey),
      public_key_spki,
      subject: subject.subject,
      sans,
      key_usages: key_usages as KeyUsageName[],
      extended_key_usages: template.extended_key_usages as ExtendedKeyUsageName[],
      not_after: new Date(Date.now() + ttl * 1000),
      crl_urls: [urls.crl],
      ca_issuer_urls: [urls.certificate],
    }),
  )

  let private_key: IssuedPrivateKey | undefined
  if (keyPair && key.kind === 'keygen') {
    if (key.keygen.format === 'pem') {
      private_key = { format: 'pem', pem: await leafPrivateKeyToPem(keyPair.privateKey) }
    } else {
      const chain = [caCert.certificate_der, ...(caCert.chain_pem.trim() ? parseCertificateBundle(caCert.chain_pem) : [])]
      const p12 = await pki(() =>
        buildPkcs12({ private_key: keyPair!.privateKey, certificate: built.der, chain, password: key.keygen.pkcs12_password!, friendly_name: subject.common_name ?? sans[0]?.value }),
      )
      private_key = { format: 'pkcs12', pkcs12_base64: toBase64(p12) }
      p12.fill(0)
    }
  }
  // Nothing below needs the key pair; drop it so it is not kept alive by this scope.
  keyPair = null

  let row: CertificateRow
  try {
    row = await withTransaction(ctx, async (tx) => {
      await assertStillIssuing(tx, ca.id, template.id)
      const [inserted] = await tx
        .insert(schema.certificates)
        .values({
          ca_id: ca.id,
          ca_cert_id: caCert.id,
          template_id: template.id,
          source: request.source,
          serial: built.serial,
          subject_dn: built.subject,
          issuer_dn: built.issuer,
          common_name: subject.common_name,
          sans: built.sans,
          key_algorithm,
          key_usages,
          extended_key_usages: template.extended_key_usages,
          not_before: built.not_before,
          not_after: built.not_after,
          fingerprint_sha256: built.fingerprint_sha256,
          certificate_der: built.der,
          csr_pem: key.kind === 'csr' ? key.csr.pem : null,
          key_generated: key.kind === 'keygen',
          requested_by_user_id: isProtocolRequester(actor) ? null : actor.id,
          requested_by_api_key_id: !isProtocolRequester(actor) && actor.kind === 'api_key' ? (actor.api_key_id ?? null) : null,
        })
        .returning()
      const tag_ids =
        request.tags.from === 'ids'
          ? (await replaceTags(tx, schema.certificateTags, inserted!.id, request.tags.ids)).added
          : await copyTagsToCertificate(tx, inserted!.id, request.tags.from === 'template' ? { template_id: template.id } : { certificate_id: request.tags.certificate_id })
      const { event, data } = await finish(tx, inserted!)
      // Ids and facts only: no key, no password, no PKCS#12.
      await recordEvent(
        ctx,
        requestEvent(actor, event, subjectOf(inserted!.id), {
          template_id: template.id,
          ca_id: ca.id,
          serial: inserted!.serial,
          fingerprint_sha256: inserted!.fingerprint_sha256,
          source: request.source,
          key_generated: inserted!.key_generated,
          key_algorithm,
          not_after: inserted!.not_after.toISOString(),
          not_after_clamped: built.not_after_clamped,
          tag_ids,
          ...data,
        }),
        tx,
      )
      return inserted!
    })
  } catch (error) {
    if (isUniqueViolation(error)) throw new ConflictError('A certificate with this serial or fingerprint already exists; try again', 'conflict')
    throw error
  }
  return { certificate: row, not_after_clamped: built.not_after_clamped, ignored_subject_fields: subject.ignored, ...(private_key ? { private_key } : {}) }
}

/**
 * Issue a leaf certificate with a template. With a CSR, its signature is verified (proof of
 * possession), its key must be an algorithm the template allows, and SANs come from the request
 * or else from the CSR. With `keygen` (if the template allows it) certifly generates the key pair
 * and returns the private key once, as PEM or as PKCS#12 with the caller's password. Every SAN
 * must match the template's rules and the CA's name constraints; key usage and extended key
 * usage always come from the template; the lifetime may not exceed the template's maximum, and
 * is cut back to the CA's own end (reported as `not_after_clamped`). Operators and admins, also
 * through API keys.
 */
export async function issueCertificate(ctx: Context, actor: Actor, input: IssueCertificateInput): Promise<IssueResult> {
  authorize(certificatePolicy, actor, 'issue', undefined)
  return issueFromInput(ctx, actor, input)
}

/**
 * Issue for a protocol client (EST, ACME) that has authenticated itself. Same rules and same
 * pipeline as `issueCertificate`; the caller has done the authorization.
 */
export function issueCertificateAs(ctx: Context, requester: ProtocolRequester, input: IssueCertificateInput): Promise<IssueResult> {
  return issueFromInput(ctx, requester, input)
}

async function issueFromInput(ctx: Context, actor: Actor | ProtocolRequester, input: IssueCertificateInput): Promise<IssueResult> {
  const template = await findTemplateForIssue(ctx.db, input.template_id)
  checkKeyInput(template, input)
  let key: KeySource
  let sans = input.sans
  let subject_attributes: DnAttribute[] = []
  if (input.csr) {
    const csr = await pki(() => parseCsr(input.csr!.trim()))
    if (!sans && csr.unsupported_sans.length) {
      throw new ValidationError(`The CSR asks for SANs certifly cannot issue: ${csr.unsupported_sans.join(', ')}`, 'invalid_san', { unsupported: csr.unsupported_sans })
    }
    sans ??= csr.sans
    subject_attributes = csr.subject_attributes
    key = { kind: 'csr', csr }
  } else key = { kind: 'keygen', keygen: input.keygen! }
  const tags: TagSource = input.tag_ids !== undefined ? { from: 'ids', ids: await checkTagIds(ctx.db, input.tag_ids) } : { from: 'template' }

  return issue(
    ctx,
    actor,
    { template, key, common_name: input.common_name, subject_attributes, sans: sans ?? [], ttl_seconds: input.ttl_seconds, source: input.source, tags },
    async () => ({ event: 'certificates.issue', data: {} }),
  )
}

export interface RenewCertificateInput {
  /** A new CSR. Without one, the stored CSR is used again, if there is one. */
  csr?: string
  /** A new key pair. Required to renew a certificate whose key certifly generated, unless a CSR is sent. */
  keygen?: KeygenInput
  ttl_seconds?: number
  source: IssueSource
}

/**
 * Renew a certificate: issue a new one with the same template, subject and SANs, checked again
 * against the template as it is now. The key comes from a new CSR, the stored CSR, or a new
 * generated key pair. The new certificate gets the old one's tags. The old certificate becomes
 * `superseded`, pointing at the new one.
 */
export async function renewCertificate(ctx: Context, actor: Actor, id: string, input: RenewCertificateInput): Promise<IssueResult> {
  authorize(certificatePolicy, actor, 'renew', undefined)
  return renewForActor(ctx, actor, id, input)
}

/** Renew for a protocol client that has proven it holds the certificate (EST re-enrollment). */
export function renewCertificateAs(ctx: Context, requester: ProtocolRequester, id: string, input: RenewCertificateInput): Promise<IssueResult> {
  return renewForActor(ctx, requester, id, input)
}

async function renewForActor(ctx: Context, actor: Actor | ProtocolRequester, id: string, input: RenewCertificateInput): Promise<IssueResult> {
  const [old] = await ctx.db.select().from(schema.certificates).where(eq(schema.certificates.id, id))
  if (!old) throw new NotFoundError('Certificate not found')
  if (old.status !== 'active') throw new ConflictError(`A ${old.status} certificate cannot be renewed`, 'certificate_not_renewable')
  if (!old.template_id) throw new ConflictError('Only certificates issued with a template can be renewed', 'certificate_not_renewable')
  const template = await findTemplateForIssue(ctx.db, old.template_id)

  const csrText = input.csr ?? (input.keygen ? undefined : (old.csr_pem ?? undefined))
  checkKeyInput(template, { csr: csrText, keygen: input.keygen })
  const key: KeySource = csrText ? { kind: 'csr', csr: await pki(() => parseCsr(csrText.trim())) } : { kind: 'keygen', keygen: input.keygen! }

  return issue(
    ctx,
    actor,
    {
      template,
      key,
      subject_attributes: await pki(() => parseDn(old.subject_dn)),
      sans: old.sans,
      ttl_seconds: input.ttl_seconds,
      source: input.source,
      tags: { from: 'certificate', certificate_id: old.id },
    },
    async (tx, row) => {
      const [locked] = await tx.select({ status: schema.certificates.status }).from(schema.certificates).where(eq(schema.certificates.id, old.id)).for('update')
      if (locked?.status !== 'active') throw new ConflictError('The certificate was renewed or revoked meanwhile', 'certificate_not_renewable')
      await tx.update(schema.certificates).set({ status: 'superseded', superseded_by_id: row.id }).where(eq(schema.certificates.id, old.id))
      return { event: 'certificates.renew', data: { previous_certificate_id: old.id } }
    },
  )
}

// ---------------------------------------------------------------------------------------------
// Read

const { certificate_der: _der, csr_pem: _csr, ...listColumns } = getTableColumns(schema.certificates)
export type CertificateListFields = Omit<CertificateRow, 'certificate_der' | 'csr_pem'>

const caSummary = { id: schema.certificateAuthorities.id, name: schema.certificateAuthorities.name, slug: schema.certificateAuthorities.slug }
const templateSummary = {
  id: schema.templates.id,
  name: schema.templates.name,
  slug: schema.templates.slug,
  status: schema.templates.status,
  renew_before_days: schema.templates.renew_before_days,
}

export interface CertificateListRow {
  certificate: CertificateListFields
  /** Null for certificates imported into the inventory. */
  ca: { id: string; name: string; slug: string } | null
  template: { id: string; name: string; slug: string; status: TemplateRow['status']; renew_before_days: number } | null
  tags: TagSummary[]
}

export type CertificateSort = 'newest' | 'expiry' | 'name'

/** The filters `certificates.list` and `certificate_groups.list` share. */
export interface CertificateFilters {
  status?: CertificateStatus
  ca_id?: string
  template_id?: string
  source?: CertificateSource
  /** Only inventory imports (true), or only certificates certifly issued (false). */
  imported?: boolean
  /** Only certificates whose notAfter is before this. */
  expiring_before?: Date
  /** Part of the common name, a SAN, or the start of the serial or fingerprint. */
  query?: string
  /** Only certificates that carry every one of these tags. */
  tag_ids?: string[]
  /** Only certificates without tags (true), or only those with at least one (false). */
  untagged?: boolean
}

export interface ListCertificatesInput extends CursorInput, CertificateFilters {
  /** `newest` first (default), soonest `expiry` first, or by `name` (common name, else first SAN, else subject). */
  sort?: CertificateSort
}

function statusFilter(status: CertificateStatus, now: Date): SQL | undefined {
  const c = schema.certificates
  if (status === 'active') return and(eq(c.status, 'active'), gt(c.not_after, now))
  if (status === 'expired') return or(eq(c.status, 'expired'), and(eq(c.status, 'active'), lte(c.not_after, now)))
  return eq(c.status, status)
}

const likePattern = (text: string) => `%${text.replace(/[\\%_]/g, (m) => `\\${m}`)}%`

const hasTag = (tag_id: string) =>
  sql`exists (select 1 from ${schema.certificateTags} where ${schema.certificateTags.certificate_id} = ${schema.certificates.id} and ${schema.certificateTags.tag_id} = ${tag_id})`
const hasAnyTag = sql`exists (select 1 from ${schema.certificateTags} where ${schema.certificateTags.certificate_id} = ${schema.certificates.id})`

function certificateFilters(input: CertificateFilters, now: Date): (SQL | undefined)[] {
  const c = schema.certificates
  const filters: (SQL | undefined)[] = []
  if (input.status) filters.push(statusFilter(input.status, now))
  if (input.ca_id) filters.push(eq(c.ca_id, input.ca_id))
  if (input.template_id) filters.push(eq(c.template_id, input.template_id))
  if (input.source) filters.push(eq(c.source, input.source))
  if (input.imported !== undefined) filters.push(input.imported ? eq(c.source, 'import') : ne(c.source, 'import'))
  if (input.expiring_before) filters.push(lte(c.not_after, input.expiring_before))
  for (const tag_id of new Set(input.tag_ids ?? [])) filters.push(hasTag(tag_id))
  if (input.untagged !== undefined) filters.push(input.untagged ? sql`not ${hasAnyTag}` : hasAnyTag)
  const query = input.query?.trim().toLowerCase()
  if (query) {
    const hex = query.replace(/[:\s]/g, '')
    filters.push(
      or(
        ilike(c.common_name, likePattern(query)),
        ilike(sql`${c.sans}::text`, likePattern(query)),
        ...(/^[0-9a-f]{4,}$/.test(hex) ? [ilike(c.serial, `${hex}%`), ilike(c.fingerprint_sha256, `${hex}%`)] : []),
      ),
    )
  }
  return filters
}

/** What the name sort compares: the common name, else the first SAN, else the subject DN. */
const sortName = sql`lower(coalesce(${schema.certificates.common_name}, ${schema.certificates.sans}->0->>'value', ${schema.certificates.subject_dn}))`

function sortKeys(sort: CertificateSort | undefined): SortKey[] {
  const c = schema.certificates
  switch (sort) {
    case 'expiry':
      return [
        { expr: c.not_after, type: 'timestamptz', direction: 'asc' },
        { expr: c.id, type: 'uuid', direction: 'asc' },
      ]
    case 'name':
      return [
        { expr: sortName, type: 'text', direction: 'asc' },
        { expr: c.id, type: 'uuid', direction: 'asc' },
      ]
    default:
      return [
        { expr: c.created_at, type: 'timestamptz', direction: 'desc' },
        { expr: c.id, type: 'uuid', direction: 'desc' },
      ]
  }
}

/** Leaf certificates with their CA, template and tags, filtered, by keyset. */
export async function listCertificates(ctx: Context, actor: Actor, input: ListCertificatesInput, now = new Date()) {
  authorize(certificatePolicy, actor, 'read', undefined)
  const c = schema.certificates
  const page = keyset(sortKeys(input.sort), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, certificate: listColumns, ca: caSummary, template: templateSummary })
    .from(c)
    .leftJoin(schema.certificateAuthorities, eq(schema.certificateAuthorities.id, c.ca_id))
    .leftJoin(schema.templates, eq(schema.templates.id, c.template_id))
    .where(and(...certificateFilters(input, now), page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  const tags = await certificateTagsOf(ctx.db, result.rows.map((row) => row.certificate.id))
  return { rows: result.rows.map((row) => ({ ...row, tags: tags.get(row.certificate.id) ?? [] })), next_cursor: result.next_cursor } as {
    rows: CertificateListRow[]
    next_cursor: string | null
  }
}

export type CertificateGroupBy = 'tag' | 'template' | 'ca' | 'status'

export interface ListCertificateGroupsInput extends CertificateFilters {
  group_by: CertificateGroupBy
}

/** The list filter that returns exactly one group's certificates, merged into the other filters. */
export type CertificateGroupFilter = { tag_ids: string[] } | { untagged: true } | { template_id: string } | { ca_id: string } | { imported: true } | { status: CertificateStatus }

export interface CertificateGroup {
  /** A tag, template or CA id, a status, or `untagged` / `imported`. */
  key: string
  /** The tag, template or CA name; null for `untagged`, `imported` and statuses, which the UI names. */
  label: string | null
  /** The tag's colour; null for every other group. */
  color: TagSummary['color'] | null
  count: number
  /** Active and running out within 30 days. */
  expiring_within_30_days: number
  filter: CertificateGroupFilter
}

const STATUS_ORDER: CertificateStatus[] = ['active', 'expired', 'revoked', 'superseded']

/**
 * The certificates matching the list filters, counted per tag, template, CA or status. A
 * certificate with two tags counts in both tag groups; certificates without tags form the
 * `untagged` group, last. Imported certificates have neither CA nor template and form the
 * `imported` group, last. Only groups with certificates are returned. Each group's `filter`,
 * merged into the same filters, lists exactly its certificates.
 */
export async function listCertificateGroups(ctx: Context, actor: Actor, input: ListCertificateGroupsInput, now = new Date()): Promise<CertificateGroup[]> {
  authorize(certificatePolicy, actor, 'read', undefined)
  const c = schema.certificates
  const where = and(...certificateFilters(input, now))
  const soon = and(eq(c.status, 'active'), gt(c.not_after, now), lte(c.not_after, new Date(now.getTime() + 30 * DAY_MS)))
  const counts = {
    count: sql<number>`count(*)`.mapWith(Number),
    expiring_within_30_days: sql<number>`count(*) filter (where ${soon})`.mapWith(Number),
  }
  const byLabel = (a: CertificateGroup, b: CertificateGroup) => (a.label ?? '').toLowerCase().localeCompare((b.label ?? '').toLowerCase()) || a.key.localeCompare(b.key)

  switch (input.group_by) {
    case 'tag': {
      const t = schema.tags
      const rows = await ctx.db
        .select({ id: t.id, name: t.name, color: t.color, ...counts })
        .from(c)
        .innerJoin(schema.certificateTags, eq(schema.certificateTags.certificate_id, c.id))
        .innerJoin(t, eq(t.id, schema.certificateTags.tag_id))
        .where(where)
        .groupBy(t.id)
      const [untagged] = await ctx.db.select(counts).from(c).where(and(where, sql`not ${hasAnyTag}`))
      const groups: CertificateGroup[] = rows.map((row) => ({ key: row.id, label: row.name, color: row.color, count: row.count, expiring_within_30_days: row.expiring_within_30_days, filter: { tag_ids: [row.id] } }))
      groups.sort(byLabel)
      if (untagged?.count) groups.push({ key: 'untagged', label: null, color: null, ...untagged, filter: { untagged: true } })
      return groups
    }
    case 'template':
    case 'ca': {
      const table = input.group_by === 'template' ? schema.templates : schema.certificateAuthorities
      const column = input.group_by === 'template' ? c.template_id : c.ca_id
      const rows = await ctx.db
        .select({ id: column, name: table.name, ...counts })
        .from(c)
        .leftJoin(table, eq(table.id, column))
        .where(where)
        .groupBy(column, table.name)
      const groups: CertificateGroup[] = []
      let imported: CertificateGroup | null = null
      for (const row of rows) {
        const base = { color: null, count: row.count, expiring_within_30_days: row.expiring_within_30_days }
        // Only imported certificates lack a CA and a template.
        if (!row.id) imported = { key: 'imported', label: null, ...base, filter: { imported: true } }
        else groups.push({ key: row.id, label: row.name, ...base, filter: input.group_by === 'template' ? { template_id: row.id } : { ca_id: row.id } })
      }
      groups.sort(byLabel)
      if (imported) groups.push(imported)
      return groups
    }
    case 'status': {
      const status = sql<CertificateStatus>`case when ${c.status} = 'active' and ${c.not_after} <= ${now.toISOString()}::timestamptz then 'expired' else ${c.status}::text end`
      // By position: the expression carries a parameter, which a repeated GROUP BY would not match.
      const rows = await ctx.db.select({ status, ...counts }).from(c).where(where).groupBy(sql`1`)
      return STATUS_ORDER.flatMap((key) => {
        const row = rows.find((r) => r.status === key)
        return row ? [{ key, label: null, color: null, count: row.count, expiring_within_30_days: row.expiring_within_30_days, filter: { status: key } }] : []
      })
    }
    default:
      throw new ValidationError('group_by must be tag, template, ca or status')
  }
}

export interface CertificateDetail extends CertificateListRow {
  certificate: CertificateRow
  info: CertificateInfo
  /** The issuing CA's certificate, then its chain up to the root; empty for imported certificates. */
  chain_pem: string
  /** The certificate this one replaced on renewal. */
  supersedes_id: string | null
}

/** One certificate with its decoded fields and its chain. Never a private key: certifly has none. */
export async function getCertificate(ctx: Context, actor: Actor, id: string): Promise<CertificateDetail> {
  authorize(certificatePolicy, actor, 'read', undefined)
  const c = schema.certificates
  const [row] = await ctx.db
    .select({ certificate: c, ca: caSummary, template: templateSummary, issuer_der: schema.caCertificates.certificate_der, issuer_chain: schema.caCertificates.chain_pem })
    .from(c)
    .leftJoin(schema.certificateAuthorities, eq(schema.certificateAuthorities.id, c.ca_id))
    .leftJoin(schema.caCertificates, eq(schema.caCertificates.id, c.ca_cert_id))
    .leftJoin(schema.templates, eq(schema.templates.id, c.template_id))
    .where(eq(c.id, id))
  if (!row) throw new NotFoundError('Certificate not found')
  const [previous] = await ctx.db.select({ id: c.id }).from(c).where(eq(c.superseded_by_id, id))
  const tags = await certificateTagsOf(ctx.db, [id])
  return {
    certificate: row.certificate,
    ca: row.ca,
    template: row.template,
    tags: tags.get(id) ?? [],
    info: await inspectCertificate(row.certificate.certificate_der),
    chain_pem: row.issuer_der ? certificateToPem(row.issuer_der) + (row.issuer_chain ?? '') : '',
    supersedes_id: previous?.id ?? null,
  }
}

export interface UpdateCertificateInput {
  /** Replaces the certificate's tags. */
  tag_ids: string[]
}

/**
 * Change a certificate's tags. Works on every certificate, imported ones too; tags only sort and
 * group the list, so operators and admins may do it, also with API keys, without step-up.
 */
export async function updateCertificate(ctx: Context, actor: Actor, id: string, input: UpdateCertificateInput): Promise<void> {
  authorize(certificatePolicy, actor, 'update', undefined)
  const tag_ids = await checkTagIds(ctx.db, input.tag_ids)
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx.select({ id: schema.certificates.id }).from(schema.certificates).where(eq(schema.certificates.id, id)).for('update')
    if (!row) throw new NotFoundError('Certificate not found')
    const { added, removed } = await replaceTags(tx, schema.certificateTags, id, tag_ids)
    if (!added.length && !removed.length) return
    await recordEvent(ctx, eventFor(actor, 'certificates.update', subjectOf(id), { added_tag_ids: added, removed_tag_ids: removed }), tx)
  })
}

/** Counts for the dashboard. */
export async function certificateStats(ctx: Context, actor: Actor, now = new Date()) {
  authorize(certificatePolicy, actor, 'read', undefined)
  authorize(caPolicy, actor, 'read', undefined)
  const c = schema.certificates
  const live = and(eq(c.status, 'active'), gt(c.not_after, now))!
  const within = (days: number) => and(live, lte(c.not_after, new Date(now.getTime() + days * DAY_MS)))!
  const [stats] = await ctx.db
    .select({
      active: sql<number>`count(*) filter (where ${live})`.mapWith(Number),
      expiring_within_7_days: sql<number>`count(*) filter (where ${within(7)})`.mapWith(Number),
      expiring_within_30_days: sql<number>`count(*) filter (where ${within(30)})`.mapWith(Number),
      expired: sql<number>`count(*) filter (where ${statusFilter('expired', now)!})`.mapWith(Number),
      issued_last_7_days: sql<number>`count(*) filter (where ${and(ne(c.source, 'import'), gt(c.created_at, new Date(now.getTime() - 7 * DAY_MS)))})`.mapWith(Number),
      // Revoked and not expired yet, so still on a CRL.
      revoked: sql<number>`count(*) filter (where ${and(eq(c.status, 'revoked'), gt(c.not_after, now))})`.mapWith(Number),
      imported_expiring_within_30_days: sql<number>`count(*) filter (where ${and(within(30), eq(c.source, 'import'))})`.mapWith(Number),
    })
    .from(c)
  const [cas] = await ctx.db.select({ active: count() }).from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.status, 'active'))
  const [revokedCas] = await ctx.db.select({ n: count() }).from(schema.certificateAuthorities).where(isNotNull(schema.certificateAuthorities.revoked_at))
  return { ...stats!, active_cas: cas?.active ?? 0, revoked_cas: revokedCas?.n ?? 0 }
}

