import { toBase64, toDer, pemDecodeAll, parseCertificate, bytes } from './encoding'
import { PkiError } from './errors'
import { buildPkcs7CertsOnly } from './pkcs'
import type { CertificateInput } from './encoding'

const CSR_LABELS = ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'] as const

/** Base64 (standard or URL-safe, padded or not) of a compact text, whitespace ignored. */
function decodeBase64Text(text: string, what: string): Uint8Array<ArrayBuffer> {
  const compact = text.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!compact || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) throw new PkiError('invalid_input', `The ${what} is not valid base64`)
  const binary = atob(compact.replace(/=+$/, ''))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/**
 * The DER of the PKCS#10 request in an EST enrollment body (RFC 7030 §4.2.1): base64 of the DER,
 * with or without line breaks. Clients that send PEM or the raw DER are accepted too.
 */
export function decodeEstRequestBody(body: Uint8Array | string): Uint8Array<ArrayBuffer> {
  if (typeof body !== 'string' && body[0] === 0x30) return bytes(body)
  const text = typeof body === 'string' ? body : new TextDecoder().decode(body)
  if (text.includes('-----BEGIN')) return toDer(text, CSR_LABELS)
  return decodeBase64Text(text, 'request')
}

/**
 * Certs-only CMS SignedData as EST sends it (RFC 7030 §4.1.3, §4.2.3): the DER as base64 in
 * lines of 64 characters.
 */
export function buildEstCertificates(certificates: readonly CertificateInput[]): string {
  return toBase64(buildPkcs7CertsOnly(certificates)).replace(/.{1,64}/g, '$&\n')
}

/**
 * The client certificate a TLS proxy passes on in a request header, as DER. Accepts what the
 * common proxies send:
 *  - Traefik `passTLSClientCert` with `pem: true`: the PEM without its delimiters and line
 *    breaks, i.e. base64 of the DER, several certificates separated by commas;
 *  - nginx `$ssl_client_escaped_cert`: URL-encoded PEM;
 *  - plain PEM (also with its line breaks folded into spaces) and base64 DER (Caddy's
 *    `certificate_der_base64`).
 * Only the first certificate is used: proxies list the client's own certificate first.
 */
export function parseForwardedClientCertificate(value: string): Uint8Array<ArrayBuffer> {
  let text = value.trim().replace(/^"(.*)"$/s, '$1')
  if (!text) throw new PkiError('invalid_certificate', 'The client certificate header is empty')
  if (text.includes('%')) {
    try {
      text = decodeURIComponent(text)
    } catch {
      throw new PkiError('invalid_certificate', 'The client certificate header is not valid URL encoding')
    }
  }
  let der: Uint8Array<ArrayBuffer>
  if (text.includes('-----BEGIN')) {
    const first = pemDecodeAll(text)[0]
    if (!first || first.label !== 'CERTIFICATE') throw new PkiError('invalid_certificate', 'The client certificate header holds no certificate')
    der = first.der
  } else {
    der = decodeBase64Text(text.split(',')[0]!, 'client certificate')
  }
  parseCertificate(der)
  return der
}
