import {
  BACKDATE_MS,
  canSignCertificates,
  checkPublicationUrls,
  EXTENDED_KEY_USAGE_OIDS,
  issueCertificate,
  KEY_USAGE_FLAGS,
  keyIdentifier,
  toSeconds,
  type ExtendedKeyUsageName,
  type IssuedCertificate,
  type KeyUsageName,
} from './certificate'
import { bytes, parseCertificate, type CertificateInput } from './encoding'
import { PkiError } from './errors'
import { describePublicKey } from './keys'
import { checkNameConstraints, readNameConstraints } from './name-constraints'
import { dnToName, normalizeSans, parseDn, type DnAttribute, type San } from './names'
import { generateSerial } from './serial'
import type { Signer } from './signer'
import * as x509 from './x509'

const LEAF_KEY_USAGES: readonly KeyUsageName[] = ['digital_signature', 'non_repudiation', 'key_encipherment', 'data_encipherment', 'key_agreement']
// RFC 5480 §3: an EC key cannot encrypt, so these make no sense for it.
const RSA_ONLY_USAGES: readonly KeyUsageName[] = ['key_encipherment', 'data_encipherment']

export interface LeafCertificateParams {
  issuer_certificate: CertificateInput
  /** Holds the issuing CA's key. */
  signer: Signer
  /** The subject's public key, from a verified CSR or a key generated for the request. */
  public_key_spki: Uint8Array
  /** May be empty when SANs are given; the SAN extension is then critical. */
  subject?: string | DnAttribute[] | null
  sans: readonly San[]
  /** From the template, never from the CSR. */
  key_usages: readonly KeyUsageName[]
  /** From the template, never from the CSR. */
  extended_key_usages: readonly ExtendedKeyUsageName[]
  /** The requested end; clamped to the issuer's notAfter. */
  not_after: Date
  crl_urls: readonly string[]
  ca_issuer_urls: readonly string[]
  serial?: string
  now?: Date
}

export interface LeafCertificate extends IssuedCertificate {
  sans: San[]
  /** True when notAfter was cut back to the issuer's notAfter. */
  not_after_clamped: boolean
}

/**
 * Builds and signs an end-entity certificate. Every name is checked against the issuer's name
 * constraints, and a violation refuses the request rather than issuing a certificate that
 * relying parties would reject.
 */
export async function buildLeafCertificate(params: LeafCertificateParams): Promise<LeafCertificate> {
  const issuer = parseCertificate(params.issuer_certificate)
  const now = toSeconds(params.now ?? new Date())
  const spki = bytes(params.public_key_spki)
  const key = await describePublicKey(spki)

  if (!canSignCertificates(issuer)) throw new PkiError('issuer_not_ca', 'The issuer is not a CA with keyCertSign')
  if (issuer.notAfter.getTime() <= now.getTime()) throw new PkiError('issuer_expired', 'The issuing CA certificate has expired')
  if (issuer.notBefore.getTime() > now.getTime()) throw new PkiError('issuer_expired', 'The issuing CA certificate is not valid yet')

  const subjectAttributes = Array.isArray(params.subject) ? params.subject : params.subject ? parseDn(params.subject) : []
  const subject = subjectAttributes.length ? dnToName(subjectAttributes) : null
  const sans = normalizeSans(params.sans ?? [])
  if (!subject && sans.length === 0) throw new PkiError('invalid_input', 'A certificate needs a subject or at least one SAN')

  const usages = [...new Set(params.key_usages)]
  if (usages.length === 0) throw new PkiError('invalid_input', 'At least one key usage is required')
  for (const usage of usages) {
    if (!LEAF_KEY_USAGES.includes(usage)) throw new PkiError('invalid_input', `Key usage ${usage} is not allowed for a leaf certificate`)
    if (key.type === 'ec' && RSA_ONLY_USAGES.includes(usage)) throw new PkiError('invalid_input', `Key usage ${usage} does not apply to EC keys`)
  }
  const ekus = [...new Set(params.extended_key_usages)]
  if (ekus.length === 0 || ekus.some((e) => !(e in EXTENDED_KEY_USAGE_OIDS))) {
    throw new PkiError('invalid_input', `Extended key usages must be among ${Object.keys(EXTENDED_KEY_USAGE_OIDS).join(', ')}`)
  }

  const nc = readNameConstraints(issuer)
  if (nc) {
    const violations = checkNameConstraints(nc, { sans, subject: subject?.toString() ?? null })
    if (violations.length) throw new PkiError('name_constraints_violation', "A name is outside the issuer's name constraints", { violations })
  }

  const not_before = new Date(Math.max(now.getTime() - BACKDATE_MS, issuer.notBefore.getTime()))
  const requested = toSeconds(params.not_after)
  if (requested.getTime() <= now.getTime()) throw new PkiError('invalid_validity', 'notAfter must be in the future')
  const not_after_clamped = requested.getTime() > issuer.notAfter.getTime()
  const not_after = not_after_clamped ? issuer.notAfter : requested

  const crl_urls = checkPublicationUrls(params.crl_urls, 'CRL distribution point')
  const ca_issuer_urls = checkPublicationUrls(params.ca_issuer_urls, 'CA issuers')
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(usages.reduce((flags, u) => flags | KEY_USAGE_FLAGS[u], 0), true),
    new x509.ExtendedKeyUsageExtension(ekus.map((e) => EXTENDED_KEY_USAGE_OIDS[e])),
    await x509.SubjectKeyIdentifierExtension.create(spki),
    new x509.AuthorityKeyIdentifierExtension(await keyIdentifier(issuer)),
  ]
  if (sans.length) {
    // RFC 5280 §4.2.1.6: with an empty subject the SAN extension carries the identity and is critical.
    const names = sans.map((s) => ({ type: s.type === 'uri' ? 'url' : s.type, value: s.value }) as x509.JsonGeneralName)
    extensions.push(new x509.SubjectAlternativeNameExtension(names, subject === null))
  }
  if (crl_urls.length) extensions.push(new x509.CRLDistributionPointsExtension(crl_urls))
  if (ca_issuer_urls.length) extensions.push(new x509.AuthorityInfoAccessExtension({ caIssuers: ca_issuer_urls }))

  const issued = await issueCertificate({
    signer: params.signer,
    serial: params.serial ?? generateSerial(),
    subject,
    issuer: issuer.subjectName,
    public_key_spki: spki,
    not_before,
    not_after,
    extensions,
    verify_with: issuer.publicKey,
  })
  return { ...issued, sans, not_after_clamped }
}
