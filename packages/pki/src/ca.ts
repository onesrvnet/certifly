import {
  BACKDATE_MS,
  basicConstraints,
  canSignCertificates,
  checkPathLength,
  checkPublicationUrls,
  issueCertificate,
  KEY_USAGE_FLAGS,
  keyIdentifier,
  keyUsages,
  toSeconds,
  type IssuedCertificate,
} from './certificate'
import { bytes, certificateToPem, parseCertificate, parseCertificateBundle, type CertificateInput } from './encoding'
import { PkiError } from './errors'
import { describePublicKey } from './keys'
import {
  hasPermittedSubtrees,
  isEmptyNameConstraints,
  nameConstraintsExtension,
  nameConstraintsSubsetProblems,
  normalizeNameConstraints,
  readNameConstraints,
  type NameConstraintsInput,
} from './name-constraints'
import { dnEquals, dnToName, type DnAttribute } from './names'
import { generateSerial } from './serial'
import type { Signer } from './signer'
import * as x509 from './x509'

const CA_KEY_USAGE = KEY_USAGE_FLAGS.key_cert_sign | KEY_USAGE_FLAGS.crl_sign

export interface RootCertificateParams {
  signer: Signer
  public_key_spki: Uint8Array
  subject: string | DnAttribute[]
  /** Defaults to now minus five minutes. */
  not_before?: Date
  not_after: Date
  /** null for unlimited. */
  path_length?: number | null
  /** Optional for a root. */
  name_constraints?: NameConstraintsInput | null
  /** Defaults to a fresh random serial. */
  serial?: string
}

/**
 * A self-signed root. BasicConstraints and KeyUsage(keyCertSign, cRLSign) are critical, AKI
 * equals the SKI, and there is no CDP or AIA: a trust anchor is not checked for revocation.
 */
export async function buildRootCertificate(params: RootCertificateParams): Promise<IssuedCertificate> {
  const spki = bytes(params.public_key_spki)
  await describePublicKey(spki)
  const path_length = checkPathLength(params.path_length)
  const name = dnToName(params.subject)
  if (name.toJSON().length === 0) throw new PkiError('invalid_dn', 'A CA needs a subject name')
  const ski = await x509.SubjectKeyIdentifierExtension.create(spki)
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(true, path_length ?? undefined, true),
    new x509.KeyUsagesExtension(CA_KEY_USAGE, true),
    ski,
    new x509.AuthorityKeyIdentifierExtension(ski.keyId),
  ]
  if (params.name_constraints && !isEmptyNameConstraints(params.name_constraints)) {
    extensions.push(nameConstraintsExtension(params.name_constraints))
  }
  return issueCertificate({
    signer: params.signer,
    serial: params.serial ?? generateSerial(),
    subject: name,
    issuer: name,
    public_key_spki: spki,
    not_before: toSeconds(params.not_before ?? new Date(Date.now() - BACKDATE_MS)),
    not_after: toSeconds(params.not_after),
    extensions,
    verify_with: new x509.PublicKey(spki),
  })
}

export interface IntermediateParams {
  /** The parent CA's certificate; `signer` must hold its key. */
  issuer_certificate: CertificateInput
  signer: Signer
  /** The new CA's public key. */
  public_key_spki: Uint8Array
  subject: string | DnAttribute[]
  /** Defaults to now minus five minutes, but never before the parent's notBefore. */
  not_before?: Date
  not_after: Date
  path_length: number | null
  /** Required, and a subset of the parent's when the parent has any. */
  name_constraints: NameConstraintsInput
  /** The parent's CRL URL(s), for the CDP. */
  crl_urls: readonly string[]
  /** The parent's certificate URL(s), for AIA caIssuers. */
  ca_issuer_urls: readonly string[]
  serial?: string
  now?: Date
}

/**
 * Signs a subordinate CA under a parent CA. Refuses when the parent cannot sign CAs, when its
 * pathLen leaves no room, when the validity is not inside the parent's, or when the requested
 * name constraints are wider than the parent's (RFC 5280 §4.2.1.9, §4.2.1.10).
 */
export async function signIntermediate(params: IntermediateParams): Promise<IssuedCertificate> {
  const parent = parseCertificate(params.issuer_certificate)
  const now = toSeconds(params.now ?? new Date())
  const spki = bytes(params.public_key_spki)
  await describePublicKey(spki)

  if (!canSignCertificates(parent)) throw new PkiError('issuer_not_ca', 'The parent is not a CA with keyCertSign')
  if (parent.notAfter.getTime() <= now.getTime()) throw new PkiError('issuer_expired', 'The parent CA certificate has expired')
  const parentPath = basicConstraints(parent)!.pathLength
  const path_length = checkPathLength(params.path_length)
  if (parentPath === 0) throw new PkiError('path_length_exceeded', 'The parent has pathLen 0 and cannot sign CA certificates')
  if (parentPath !== undefined && (path_length === null || path_length >= parentPath)) {
    throw new PkiError('path_length_exceeded', `pathLen must be below the parent's (${parentPath})`, { parent_path_length: parentPath })
  }

  const not_before = toSeconds(params.not_before ?? new Date(Math.max(now.getTime() - BACKDATE_MS, parent.notBefore.getTime())))
  const not_after = toSeconds(params.not_after)
  if (not_before.getTime() < parent.notBefore.getTime() || not_after.getTime() > parent.notAfter.getTime()) {
    throw new PkiError('validity_not_nested', "The validity must lie inside the parent's", {
      parent_not_before: parent.notBefore.toISOString(),
      parent_not_after: parent.notAfter.toISOString(),
    })
  }

  const constraints = normalizeNameConstraints(params.name_constraints)
  if (!hasPermittedSubtrees(constraints)) throw new PkiError('invalid_name_constraints', 'A subordinate CA needs at least one permitted name constraint')
  const parentConstraints = readNameConstraints(parent)
  if (parentConstraints) {
    const problems = nameConstraintsSubsetProblems(constraints, parentConstraints)
    if (problems.length) throw new PkiError('name_constraints_not_subset', "The name constraints are not a subset of the parent's", { problems })
  }

  const name = dnToName(params.subject)
  if (name.toJSON().length === 0) throw new PkiError('invalid_dn', 'A CA needs a subject name')
  const crl_urls = checkPublicationUrls(params.crl_urls, 'CRL distribution point')
  const ca_issuer_urls = checkPublicationUrls(params.ca_issuer_urls, 'CA issuers')
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(true, path_length ?? undefined, true),
    new x509.KeyUsagesExtension(CA_KEY_USAGE | KEY_USAGE_FLAGS.digital_signature, true),
    await x509.SubjectKeyIdentifierExtension.create(spki),
    new x509.AuthorityKeyIdentifierExtension(await keyIdentifier(parent)),
    nameConstraintsExtension(constraints),
  ]
  if (crl_urls.length) extensions.push(new x509.CRLDistributionPointsExtension(crl_urls))
  if (ca_issuer_urls.length) extensions.push(new x509.AuthorityInfoAccessExtension({ caIssuers: ca_issuer_urls }))

  return issueCertificate({
    signer: params.signer,
    serial: params.serial ?? generateSerial(),
    subject: name,
    issuer: parent.subjectName,
    public_key_spki: spki,
    not_before,
    not_after,
    extensions,
    verify_with: parent.publicKey,
  })
}

// ---------------------------------------------------------------------------------------------
// Externally signed CAs

export type ImportErrorCode =
  | 'invalid_certificate'
  | 'invalid_chain'
  | 'public_key_mismatch'
  | 'not_ca'
  | 'basic_constraints_not_critical'
  | 'path_length_mismatch'
  | 'missing_key_cert_sign'
  | 'missing_crl_sign'
  | 'subject_mismatch'
  | 'name_constraints_missing'
  | 'name_constraints_not_critical'
  | 'chain_incomplete'
  | 'chain_signature_invalid'
  | 'chain_issuer_not_ca'
  | 'chain_path_length_exceeded'
  | 'chain_not_valid_now'
  | 'not_yet_valid'
  | 'expired'

export interface ImportError {
  code: ImportErrorCode
  message: string
}

export interface ImportExpectation {
  /** The CA key's SubjectPublicKeyInfo DER. */
  public_key_spki: Uint8Array
  /** The pathLen requested in the CSR; null for unlimited. */
  path_length: number | null
  subject: string
  now?: Date
}

export interface ImportValidation {
  ok: boolean
  errors: ImportError[]
  /** Issuer first, root last; excludes the certificate itself. Empty when the chain did not build. */
  chain: Uint8Array<ArrayBuffer>[]
  chain_pem: string
}

async function canonicalSpki(spki: Uint8Array): Promise<Uint8Array | null> {
  try {
    const key = new x509.PublicKey(bytes(spki))
    const alg = key.algorithm as Algorithm & { namedCurve?: string }
    const params = alg.name === 'ECDSA' ? { name: 'ECDSA', namedCurve: alg.namedCurve! } : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    const imported = await crypto.subtle.importKey('spki', bytes(spki), params, true, ['verify'])
    return new Uint8Array(await crypto.subtle.exportKey('spki', imported))
  } catch {
    return null
  }
}

function sameBytes(a: Uint8Array | null, b: Uint8Array | null): boolean {
  return !!a && !!b && a.byteLength === b.byteLength && a.every((v, i) => v === b[i])
}

function validAt(cert: x509.X509Certificate, now: Date): boolean {
  return cert.notBefore.getTime() <= now.getTime() && now.getTime() <= cert.notAfter.getTime()
}

/**
 * Checks a CA certificate signed outside certifly before it is installed: it must be for our key,
 * be a CA with the requested pathLen, keyCertSign and cRLSign, carry the expected subject and
 * critical NameConstraints, be valid now, and chain (verified link by link) to a self-signed root
 * included in `chain`.
 */
export async function validateImportedCaCertificate(
  certificate: CertificateInput,
  chain: string | readonly CertificateInput[],
  expected: ImportExpectation,
): Promise<ImportValidation> {
  const errors: ImportError[] = []
  const fail = (code: ImportErrorCode, message: string) => errors.push({ code, message })
  const result = (path: x509.X509Certificate[] = []): ImportValidation => {
    const ders = errors.length ? [] : path.map((c) => new Uint8Array(c.rawData))
    return { ok: errors.length === 0, errors, chain: ders, chain_pem: ders.map(certificateToPem).join('') }
  }
  const now = toSeconds(expected.now ?? new Date())

  let cert: x509.X509Certificate
  try {
    cert = parseCertificate(certificate)
  } catch {
    fail('invalid_certificate', 'The certificate could not be parsed')
    return result()
  }
  let pool: x509.X509Certificate[]
  try {
    pool = (typeof chain === 'string' ? parseCertificateBundle(chain) : chain).map((c) => parseCertificate(c))
  } catch {
    fail('invalid_chain', 'The chain could not be parsed')
    return result()
  }

  if (!sameBytes(await canonicalSpki(new Uint8Array(cert.publicKey.rawData)), await canonicalSpki(expected.public_key_spki))) {
    fail('public_key_mismatch', "The certificate is not for this CA's key")
  }

  const bc = basicConstraints(cert)
  if (!bc?.ca) fail('not_ca', 'The certificate is not a CA certificate (BasicConstraints CA=true is missing)')
  else {
    if (!bc.critical) fail('basic_constraints_not_critical', 'BasicConstraints must be critical')
    const actual = bc.pathLength ?? null
    if (actual !== (expected.path_length ?? null)) {
      fail('path_length_mismatch', `pathLen is ${actual ?? 'unlimited'}, expected ${expected.path_length ?? 'unlimited'}`)
    }
  }
  const usages = keyUsages(cert) ?? []
  if (!usages.includes('key_cert_sign')) fail('missing_key_cert_sign', 'KeyUsage must include keyCertSign')
  if (!usages.includes('crl_sign')) fail('missing_crl_sign', 'KeyUsage must include cRLSign, or certifly cannot publish CRLs')

  let subjectMatches = false
  try {
    subjectMatches = dnEquals(cert.subjectName, expected.subject)
  } catch {
    subjectMatches = false
  }
  if (!subjectMatches) fail('subject_mismatch', `The subject is "${cert.subject}", expected "${expected.subject}"`)

  const nc = readNameConstraints(cert)
  if (!nc) fail('name_constraints_missing', 'NameConstraints are required for a subordinate CA')
  else if (!nc.critical) fail('name_constraints_not_critical', 'NameConstraints must be critical')

  if (now.getTime() < cert.notBefore.getTime()) fail('not_yet_valid', 'The certificate is not valid yet')
  if (now.getTime() > cert.notAfter.getTime()) fail('expired', 'The certificate has expired')

  // Build the path with x509, then verify every link ourselves rather than trusting the builder.
  let path: x509.X509Certificate[] = []
  try {
    path = [...(await new x509.X509ChainBuilder({ certificates: pool }).build(cert))]
  } catch {
    path = []
  }
  const top = path.at(-1)
  if (path.length < 2 || !top || !(await top.isSelfSigned().catch(() => false))) {
    fail('chain_incomplete', 'The chain does not lead to a self-signed root; include every intermediate and the root')
    return result()
  }
  for (let i = 0; i < path.length - 1; i++) {
    const child = path[i]!
    const issuer = path[i + 1]!
    const linked = child.issuerName.toString() === issuer.subjectName.toString() && (await child.verify({ publicKey: issuer.publicKey, signatureOnly: true }).catch(() => false))
    if (!linked) fail('chain_signature_invalid', `"${child.subject}" is not signed by "${issuer.subject}"`)
    if (!canSignCertificates(issuer)) fail('chain_issuer_not_ca', `"${issuer.subject}" is not a CA with keyCertSign`)
    // `i + 1` CA certificates follow this issuer in any path through the imported CA.
    const issuerPath = basicConstraints(issuer)?.pathLength
    if (issuerPath !== undefined && issuerPath < i + 1) fail('chain_path_length_exceeded', `"${issuer.subject}" allows only ${issuerPath} CA level(s) below it`)
    if (!validAt(issuer, now)) fail('chain_not_valid_now', `"${issuer.subject}" is not valid now`)
  }
  return result(path.slice(1))
}
