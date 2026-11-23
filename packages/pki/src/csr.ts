import { checkPathLength, KEY_USAGE_FLAGS, sansOf } from './certificate'
import { bytes, pemEncode, toDer } from './encoding'
import { PkiError } from './errors'
import { describePublicKey, type PublicKeyDescription } from './keys'
import { nameConstraintsExtension, normalizeNameConstraints, type NameConstraintsInput } from './name-constraints'
import { dnToName, type DnAttribute, type San } from './names'
import { x509Signing, type Signer } from './signer'
import * as x509 from './x509'

const CSR_LABELS = ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'] as const
const ACCEPTED_HASHES = new Set(['SHA-256', 'SHA-384', 'SHA-512'])

export interface ParsedCsr {
  der: Uint8Array<ArrayBuffer>
  pem: string
  /** RFC 4514 text of the requested subject; empty when the CSR has none. */
  subject: string
  subject_attributes: DnAttribute[]
  /** Requested SANs that certifly understands, normalised. */
  sans: San[]
  /** Requested SANs of other types (or malformed ones), as `type:value`, for display. */
  unsupported_sans: string[]
  public_key: PublicKeyDescription
  /** e.g. `ECDSA/SHA-256`. */
  signature_algorithm: string
  /** Every extension the CSR asks for. Informational: KU/EKU always come from the template. */
  requested_extensions: { oid: string; critical: boolean }[]
}

/**
 * Parses a PKCS#10 request (PEM or DER) and verifies its signature, which proves the requester
 * holds the private key. Refuses unsupported keys and weak signature hashes.
 */
export async function parseCsr(input: string | Uint8Array): Promise<ParsedCsr> {
  const der = toDer(input, CSR_LABELS)
  let csr: x509.Pkcs10CertificateRequest
  try {
    csr = new x509.Pkcs10CertificateRequest(der)
  } catch {
    throw new PkiError('invalid_csr', 'Not a valid PKCS#10 certificate request')
  }
  const public_key = await describePublicKey(new Uint8Array(csr.publicKey.rawData))

  const algorithm = csr.signatureAlgorithm
  const hash = typeof algorithm?.hash === 'object' ? algorithm.hash.name : (algorithm?.hash as string | undefined)
  if (!hash || !ACCEPTED_HASHES.has(hash.toUpperCase())) {
    throw new PkiError('invalid_csr', 'The CSR must be signed with SHA-256, SHA-384 or SHA-512')
  }

  let valid = false
  try {
    valid = await csr.verify()
  } catch {
    valid = false
  }
  if (!valid) throw new PkiError('csr_signature_invalid', 'The CSR signature does not verify with its public key')

  const { sans, unsupported } = sansOf(csr)
  const subject_attributes = csr.subjectName
    .toJSON()
    .flatMap((rdn) => Object.entries(rdn).flatMap(([type, values]) => values.map((value) => ({ type, value }))))
  return {
    der,
    pem: pemEncode(der, 'CERTIFICATE REQUEST'),
    subject: csr.subject,
    subject_attributes,
    sans,
    unsupported_sans: unsupported,
    public_key,
    signature_algorithm: `${algorithm.name}/${hash.toUpperCase()}`,
    requested_extensions: csr.extensions.map((e) => ({ oid: e.type, critical: e.critical })),
  }
}

export interface CaCsrParams {
  signer: Signer
  /** The CA key's SubjectPublicKeyInfo DER, as returned when the key was generated. */
  public_key_spki: Uint8Array
  subject: string | DnAttribute[]
  /** null for unlimited. */
  path_length: number | null
  /** Required: an externally signed CA must carry name constraints. */
  name_constraints: NameConstraintsInput
}

export interface BuiltCsr {
  der: Uint8Array<ArrayBuffer>
  pem: string
}

function importParams(spki: x509.PublicKey): EcKeyImportParams | RsaHashedImportParams {
  const alg = spki.algorithm as Algorithm & { namedCurve?: string }
  return alg.name === 'ECDSA' ? { name: 'ECDSA', namedCurve: alg.namedCurve! } : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
}

/**
 * A CSR for a CA whose certificate is signed outside certifly (e.g. by an offline root). It
 * requests the extensions the root operator should keep: BasicConstraints(CA, pathLen),
 * KeyUsage(keyCertSign, cRLSign, digitalSignature), NameConstraints (all critical) and SKI.
 */
export async function buildCaCsr(params: CaCsrParams): Promise<BuiltCsr> {
  const path_length = checkPathLength(params.path_length)
  const constraints = normalizeNameConstraints(params.name_constraints)
  const spki = bytes(params.public_key_spki)
  await describePublicKey(spki)
  const publicKey = new x509.PublicKey(spki)
  const publicCryptoKey = await crypto.subtle.importKey('spki', spki, importParams(publicKey), true, ['verify'])
  const { crypto: signingCrypto, signingKey, signingAlgorithm } = x509Signing(params.signer)

  const csr = await x509.Pkcs10CertificateRequestGenerator.create(
    {
      name: dnToName(params.subject),
      keys: { privateKey: signingKey, publicKey: publicCryptoKey },
      signingAlgorithm,
      extensions: [
        new x509.BasicConstraintsExtension(true, path_length ?? undefined, true),
        new x509.KeyUsagesExtension(KEY_USAGE_FLAGS.key_cert_sign | KEY_USAGE_FLAGS.crl_sign | KEY_USAGE_FLAGS.digital_signature, true),
        nameConstraintsExtension(constraints),
        await x509.SubjectKeyIdentifierExtension.create(spki),
      ],
    },
    signingCrypto,
  )
  if (!(await csr.verify())) throw new PkiError('signer_mismatch', "The signer's key does not match the CA public key")
  const der = new Uint8Array(csr.rawData)
  return { der, pem: pemEncode(der, 'CERTIFICATE REQUEST') }
}
