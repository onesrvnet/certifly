import { bytes, certificateToPem, fingerprint, parseCertificate, toHex, type CertificateInput } from './encoding'
import { PkiError } from './errors'
import { describePublicKey, type PublicKeyDescription } from './keys'
import { readNameConstraints, type ParsedNameConstraints } from './name-constraints'
import { normalizeSan, type San } from './names'
import { x509Signing, type Signer } from './signer'
import * as x509 from './x509'

/** Clients may run a few minutes behind; new certificates start this much in the past. */
export const BACKDATE_MS = 5 * 60 * 1000

export type KeyUsageName = 'digital_signature' | 'non_repudiation' | 'key_encipherment' | 'data_encipherment' | 'key_agreement' | 'key_cert_sign' | 'crl_sign'

export const KEY_USAGE_FLAGS: Record<KeyUsageName, x509.KeyUsageFlags> = {
  digital_signature: x509.KeyUsageFlags.digitalSignature,
  non_repudiation: x509.KeyUsageFlags.nonRepudiation,
  key_encipherment: x509.KeyUsageFlags.keyEncipherment,
  data_encipherment: x509.KeyUsageFlags.dataEncipherment,
  key_agreement: x509.KeyUsageFlags.keyAgreement,
  key_cert_sign: x509.KeyUsageFlags.keyCertSign,
  crl_sign: x509.KeyUsageFlags.cRLSign,
}

export type ExtendedKeyUsageName = 'server_auth' | 'client_auth' | 'code_signing' | 'email_protection' | 'time_stamping' | 'ocsp_signing'

/** RFC 5280 §4.2.1.12 key purposes (id-kp-*). */
export const EXTENDED_KEY_USAGE_OIDS: Record<ExtendedKeyUsageName, string> = {
  server_auth: '1.3.6.1.5.5.7.3.1',
  client_auth: '1.3.6.1.5.5.7.3.2',
  code_signing: '1.3.6.1.5.5.7.3.3',
  email_protection: '1.3.6.1.5.5.7.3.4',
  time_stamping: '1.3.6.1.5.5.7.3.8',
  ocsp_signing: '1.3.6.1.5.5.7.3.9',
}

const EXTENDED_KEY_USAGE_NAMES = new Map(Object.entries(EXTENDED_KEY_USAGE_OIDS).map(([name, oid]) => [oid, name as ExtendedKeyUsageName]))

/** The result of building a certificate. */
export interface IssuedCertificate {
  der: Uint8Array<ArrayBuffer>
  pem: string
  /** Lowercase hex as encoded in the certificate. */
  serial: string
  subject: string
  issuer: string
  not_before: Date
  not_after: Date
  fingerprint_sha256: string
}

export interface CertificateInfo extends IssuedCertificate {
  fingerprint_sha1: string
  self_issued: boolean
  is_ca: boolean
  /** null when unlimited or not a CA. */
  path_length: number | null
  basic_constraints_critical: boolean | null
  key_usages: KeyUsageName[]
  /** Every EKU OID in the certificate, known or not. */
  extended_key_usages: string[]
  /** The EKUs certifly has a name for; other OIDs are only in `extended_key_usages`. */
  extended_key_usage_names: ExtendedKeyUsageName[]
  sans: San[]
  subject_key_identifier: string | null
  authority_key_identifier: string | null
  crl_urls: string[]
  ca_issuer_urls: string[]
  name_constraints: ParsedNameConstraints | null
  public_key: PublicKeyDescription | null
  public_key_spki: Uint8Array<ArrayBuffer>
}

export function basicConstraints(cert: x509.X509Certificate): x509.BasicConstraintsExtension | null {
  return cert.getExtension(x509.BasicConstraintsExtension)
}

export function keyUsageNames(flags: number): KeyUsageName[] {
  return (Object.entries(KEY_USAGE_FLAGS) as [KeyUsageName, number][]).filter(([, flag]) => (flags & flag) !== 0).map(([name]) => name)
}

export function keyUsages(cert: x509.X509Certificate): KeyUsageName[] | null {
  const ext = cert.getExtension(x509.KeyUsagesExtension)
  return ext ? keyUsageNames(ext.usages) : null
}

/**
 * Whether the certificate may sign certificates: CA=true, and keyCertSign when it has a key usage
 * extension (RFC 5280 §4.2.1.3, §4.2.1.9). Without the extension the key is not restricted; older
 * roots often leave it out.
 */
export function canSignCertificates(cert: x509.X509Certificate): boolean {
  const usages = keyUsages(cert)
  return basicConstraints(cert)?.ca === true && (usages === null || usages.includes('key_cert_sign'))
}

/** The issuer's key identifier: its SKI extension, or the RFC 5280 §4.2.1.2 method 1 hash. */
export async function keyIdentifier(cert: x509.X509Certificate): Promise<string> {
  const ski = cert.getExtension(x509.SubjectKeyIdentifierExtension)
  if (ski) return ski.keyId
  return toHex(await cert.publicKey.getKeyIdentifier())
}

export function sansOf(cert: x509.X509Certificate | x509.Pkcs10CertificateRequest): { sans: San[]; unsupported: string[] } {
  const raw = cert.getExtension('2.5.29.17')
  const ext = raw ? new x509.SubjectAlternativeNameExtension(raw.rawData) : null
  const sans: San[] = []
  const unsupported: string[] = []
  for (const name of ext?.names.toJSON() ?? []) {
    const type = name.type === 'url' ? 'uri' : name.type
    if (type === 'dns' || type === 'ip' || type === 'email' || type === 'uri') {
      try {
        sans.push(normalizeSan({ type, value: name.value }))
      } catch {
        unsupported.push(`${name.type}:${name.value}`)
      }
    } else unsupported.push(`${name.type}:${name.value}`)
  }
  return { sans, unsupported }
}

function urlsOf(names: x509.GeneralName[] | undefined): string[] {
  return (names ?? []).filter((n) => n.type === 'url').map((n) => n.value)
}

/** Reads the fields certifly stores and shows for a certificate. */
export async function inspectCertificate(input: CertificateInput): Promise<CertificateInfo> {
  const cert = parseCertificate(input)
  const der = new Uint8Array(cert.rawData)
  const bc = basicConstraints(cert)
  const aki = cert.getExtension(x509.AuthorityKeyIdentifierExtension)
  const cdp = cert.getExtension(x509.CRLDistributionPointsExtension)
  const aia = cert.getExtension(x509.AuthorityInfoAccessExtension)
  const eku = cert.getExtension(x509.ExtendedKeyUsageExtension)
  const ski = cert.getExtension(x509.SubjectKeyIdentifierExtension)
  const spki = new Uint8Array(cert.publicKey.rawData)
  let public_key: PublicKeyDescription | null = null
  try {
    public_key = await describePublicKey(spki)
  } catch {
    // Inventory imports may hold keys certifly would never issue for; still describe the rest.
  }
  return {
    der,
    pem: certificateToPem(der),
    serial: cert.serialNumber.toLowerCase(),
    subject: cert.subject,
    issuer: cert.issuer,
    not_before: cert.notBefore,
    not_after: cert.notAfter,
    fingerprint_sha256: await fingerprint(der, 'SHA-256'),
    fingerprint_sha1: await fingerprint(der, 'SHA-1'),
    self_issued: cert.subject === cert.issuer,
    is_ca: bc?.ca ?? false,
    path_length: bc?.ca && bc.pathLength !== undefined ? bc.pathLength : null,
    basic_constraints_critical: bc ? bc.critical : null,
    key_usages: keyUsages(cert) ?? [],
    extended_key_usages: (eku?.usages ?? []).map(String),
    extended_key_usage_names: (eku?.usages ?? []).flatMap((oid) => EXTENDED_KEY_USAGE_NAMES.get(String(oid)) ?? []),
    sans: sansOf(cert).sans,
    subject_key_identifier: ski?.keyId ?? null,
    authority_key_identifier: aki?.keyId ?? null,
    crl_urls: (cdp?.distributionPoints ?? []).flatMap((dp) =>
      (dp.distributionPoint?.fullName ?? []).flatMap((gn) => (gn.uniformResourceIdentifier ? [gn.uniformResourceIdentifier] : [])),
    ),
    ca_issuer_urls: urlsOf(aia?.caIssuers),
    name_constraints: readNameConstraints(cert),
    public_key,
    public_key_spki: spki,
  }
}

/** Validates CDP/AIA URLs: absolute http or https only, as relying parties fetch them. */
export function checkPublicationUrls(urls: readonly string[] | undefined, what: string): string[] {
  const list = [...(urls ?? [])]
  for (const url of list) {
    let parsed: URL
    try {
      parsed = new URL(url)
    } catch {
      throw new PkiError('invalid_input', `${what} URL is not valid: ${url}`)
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new PkiError('invalid_input', `${what} URL must use http or https: ${url}`)
  }
  return list
}

/** Certificates carry whole seconds; dropping milliseconds keeps comparisons and clamping exact. */
export function toSeconds(date: Date): Date {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) throw new PkiError('invalid_validity', 'Expected a valid date')
  return new Date(Math.floor(date.getTime() / 1000) * 1000)
}

export function checkPathLength(path_length: number | null | undefined): number | null {
  if (path_length === null || path_length === undefined) return null
  if (!Number.isInteger(path_length) || path_length < 0 || path_length > 16) {
    throw new PkiError('invalid_input', 'pathLen must be a whole number from 0 to 16, or unlimited')
  }
  return path_length
}

export interface IssueParams {
  signer: Signer
  serial: string
  subject: x509.Name | null
  issuer: x509.Name
  public_key_spki: Uint8Array
  not_before: Date
  not_after: Date
  extensions: x509.Extension[]
  /** The key the signature must verify with: the issuer's (or, for a root, the subject's own). */
  verify_with: x509.PublicKey
}

/** Builds and signs a certificate, then checks the signature so a wrong signer is caught here. */
export async function issueCertificate(params: IssueParams): Promise<IssuedCertificate> {
  if (!/^[0-9a-f]{1,40}$/i.test(params.serial)) throw new PkiError('invalid_input', 'The serial must be 1 to 40 hex digits')
  if (params.not_after.getTime() <= params.not_before.getTime()) throw new PkiError('invalid_validity', 'notAfter must be after notBefore')
  const { crypto, signingKey, signingAlgorithm } = x509Signing(params.signer)
  const cert = await x509.X509CertificateGenerator.create(
    {
      serialNumber: params.serial,
      subject: params.subject ?? undefined,
      issuer: params.issuer,
      notBefore: params.not_before,
      notAfter: params.not_after,
      publicKey: bytes(params.public_key_spki),
      signingKey,
      signingAlgorithm,
      extensions: params.extensions,
    },
    crypto,
  )
  if (!(await cert.verify({ publicKey: params.verify_with, signatureOnly: true }))) {
    throw new PkiError('signer_mismatch', "The signer's key does not match the issuer's public key")
  }
  const der = new Uint8Array(cert.rawData)
  return {
    der,
    pem: certificateToPem(der),
    serial: cert.serialNumber.toLowerCase(),
    subject: cert.subject,
    issuer: cert.issuer,
    not_before: cert.notBefore,
    not_after: cert.notAfter,
    fingerprint_sha256: await fingerprint(der),
  }
}
