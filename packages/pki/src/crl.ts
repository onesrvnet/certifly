import * as asn1js from 'asn1js'
import { keyIdentifier, keyUsages, toSeconds } from './certificate'
import { bytes, pemEncode, parseCertificate, type CertificateInput } from './encoding'
import { PkiError } from './errors'
import { normalizeSerial } from './serial'
import { x509Signing, type Signer } from './signer'
import * as x509 from './x509'

const CRL_NUMBER_OID = '2.5.29.20'

/** CRLReason codes (RFC 5280 §5.3.1). Code 7 is unused; removeFromCRL (8) only belongs in delta CRLs. */
export const REVOCATION_REASONS = {
  unspecified: 0,
  key_compromise: 1,
  ca_compromise: 2,
  affiliation_changed: 3,
  superseded: 4,
  cessation_of_operation: 5,
  certificate_hold: 6,
  privilege_withdrawn: 9,
  aa_compromise: 10,
} as const

export type RevocationReason = keyof typeof REVOCATION_REASONS

export function revocationReasonCode(reason: RevocationReason | number): number {
  const code = typeof reason === 'number' ? reason : REVOCATION_REASONS[reason]
  if (!Object.values(REVOCATION_REASONS).includes(code as never)) throw new PkiError('invalid_input', `Not a CRL reason certifly uses: ${String(reason)}`)
  return code
}

export function revocationReasonName(code: number): RevocationReason | null {
  return (Object.entries(REVOCATION_REASONS).find(([, c]) => c === code)?.[0] as RevocationReason | undefined) ?? null
}

export interface CrlEntryInput {
  /** Hex serial of the revoked certificate. */
  serial: string
  revoked_at: Date
  /** Omitted or `unspecified` leaves out the reasonCode extension, as RFC 5280 §5.3.1 asks. */
  reason?: RevocationReason | number
}

export interface CrlParams {
  issuer_certificate: CertificateInput
  signer: Signer
  /** Monotonic per CA (RFC 5280 §5.2.3). */
  crl_number: bigint | number
  this_update: Date
  next_update: Date
  entries: readonly CrlEntryInput[]
}

export interface BuiltCrl {
  der: Uint8Array<ArrayBuffer>
  pem: string
  crl_number: string
  this_update: Date
  next_update: Date
  /** True when nextUpdate was cut back to the issuer's notAfter. */
  next_update_clamped: boolean
}

/** Builds a v2 CRL with CRLNumber and AuthorityKeyIdentifier, signed by the issuing CA. */
export async function buildCrl(params: CrlParams): Promise<BuiltCrl> {
  const issuer = parseCertificate(params.issuer_certificate)
  if (!(keyUsages(issuer) ?? []).includes('crl_sign')) throw new PkiError('issuer_not_ca', 'The issuer certificate lacks the cRLSign key usage')

  const number = BigInt(params.crl_number)
  // At most 20 octets, i.e. below 2^159 so the DER INTEGER stays positive.
  if (number < 0n || number >= 1n << 159n) throw new PkiError('invalid_crl', 'The CRL number must be a non-negative integer of at most 20 octets')

  const this_update = toSeconds(params.this_update)
  const requested = toSeconds(params.next_update)
  if (requested.getTime() <= this_update.getTime()) throw new PkiError('invalid_crl', 'nextUpdate must be after thisUpdate')
  const next_update_clamped = requested.getTime() > issuer.notAfter.getTime()
  const next_update = next_update_clamped ? issuer.notAfter : requested
  if (next_update.getTime() <= this_update.getTime()) throw new PkiError('invalid_crl', 'The issuer expires before thisUpdate')

  const seen = new Set<string>()
  const entries: x509.X509CrlEntryParams[] = params.entries.map((entry) => {
    if (!/^[0-9a-f]{1,40}$/i.test(entry.serial)) throw new PkiError('invalid_crl', `Not a hex serial: ${entry.serial}`)
    const key = normalizeSerial(entry.serial)
    if (seen.has(key)) throw new PkiError('invalid_crl', `Serial ${entry.serial} is listed twice`)
    seen.add(key)
    const reason = entry.reason === undefined ? 0 : revocationReasonCode(entry.reason)
    return { serialNumber: entry.serial, revocationDate: toSeconds(entry.revoked_at), ...(reason ? { reason: reason as x509.X509CrlReason } : {}) }
  })

  const crlNumber = new x509.Extension(CRL_NUMBER_OID, false, bytes(asn1js.Integer.fromBigInt(number).toBER(false)))
  const aki = new x509.AuthorityKeyIdentifierExtension(await keyIdentifier(issuer))
  const { crypto, signingKey, signingAlgorithm } = x509Signing(params.signer)
  const crl = await x509.X509CrlGenerator.create(
    { issuer: issuer.subjectName, thisUpdate: this_update, nextUpdate: next_update, extensions: [crlNumber, aki], entries, signingKey, signingAlgorithm },
    crypto,
  )
  if (!(await crl.verify({ publicKey: issuer.publicKey }))) throw new PkiError('signer_mismatch', "The signer's key does not match the issuer's public key")
  const der = new Uint8Array(crl.rawData)
  return { der, pem: pemEncode(der, 'X509 CRL'), crl_number: number.toString(), this_update, next_update, next_update_clamped }
}
