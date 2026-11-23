import { createHash } from 'node:crypto'
import { sansOf } from './certificate'
import { parseCertificate } from './encoding'
import { PkiError } from './errors'
import { formatIp, parseIp, type San } from './names'

/** RFC 8737 §6.1: id-pe-acmeIdentifier. */
export const ACME_IDENTIFIER_OID = '1.3.6.1.5.5.7.1.31'

/** Lowercase hex SHA-256 of a key authorization, the value a tls-alpn-01 certificate carries. */
export function keyAuthorizationDigest(keyAuthorization: string): string {
  return createHash('sha256').update(keyAuthorization, 'utf8').digest('hex')
}

export interface AcmeChallengeCertificate {
  /** Every SAN in the certificate, normalised. */
  sans: San[]
  /** SANs of a kind certifly does not read, as `type:value`. */
  unsupported_sans: string[]
  /** Null when the certificate has no acmeIdentifier extension. */
  acme_identifier: { critical: boolean; digest_hex: string | null } | null
}

/**
 * Reads the certificate a tls-alpn-01 server presents (RFC 8737 §3): its SANs and the
 * acmeIdentifier extension. `digest_hex` is null when the extension is not an OCTET STRING of
 * 32 bytes.
 */
export function inspectAcmeChallengeCertificate(der: Uint8Array): AcmeChallengeCertificate {
  let cert
  try {
    cert = parseCertificate(der)
  } catch {
    throw new PkiError('invalid_certificate', 'Not a valid certificate')
  }
  const { sans, unsupported } = sansOf(cert)
  const extension = cert.getExtension(ACME_IDENTIFIER_OID)
  let acme_identifier: AcmeChallengeCertificate['acme_identifier'] = null
  if (extension) {
    const value = new Uint8Array(extension.value)
    // DER OCTET STRING (tag 0x04), length 32, then the digest.
    const digest_hex = value.length === 34 && value[0] === 0x04 && value[1] === 0x20 ? Buffer.from(value.subarray(2)).toString('hex') : null
    acme_identifier = { critical: extension.critical, digest_hex }
  }
  return { sans, unsupported_sans: unsupported, acme_identifier }
}

/**
 * The name a tls-alpn-01 client sends as SNI for an IP identifier (RFC 8738 §6): the reverse
 * DNS name of the address, `in-addr.arpa` for IPv4 and `ip6.arpa` for IPv6.
 */
export function reverseDnsName(ip: string): string {
  const address = parseIp(ip)
  if (!address) throw new PkiError('invalid_san', `Not a valid IP address: ${ip}`)
  if (address.length === 4) return `${[...address].reverse().join('.')}.in-addr.arpa`
  const nibbles = [...address].flatMap((byte) => [byte >> 4, byte & 15].map((n) => n.toString(16)))
  return `${nibbles.reverse().join('.')}.ip6.arpa`
}

/** The canonical text of an IP address, to compare addresses written differently. */
export function canonicalIp(ip: string): string | null {
  const address = parseIp(ip)
  return address ? formatIp(address) : null
}
