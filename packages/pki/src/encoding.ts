import { PkiError } from './errors'
import * as x509 from './x509'

/** A certificate as PEM text or DER bytes. */
export type CertificateInput = string | Uint8Array

export function toHex(bytes: Uint8Array | ArrayBuffer): string {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new PkiError('invalid_input', 'Not a hex string')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  try {
    const binary = atob(text)
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
    return out
  } catch {
    throw new PkiError('invalid_pem', 'The PEM body is not valid base64')
  }
}

/** A fresh copy backed by a plain ArrayBuffer, the type WebCrypto and the ASN.1 libraries want. */
export function bytes(input: Uint8Array | ArrayBuffer): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(input.byteLength)
  out.set(input instanceof Uint8Array ? input : new Uint8Array(input))
  return out
}

export function pemEncode(der: Uint8Array | ArrayBuffer, label: string): string {
  const body = toBase64(bytes(der)).replace(/.{1,64}/g, '$&\n')
  return `-----BEGIN ${label}-----\n${body}-----END ${label}-----\n`
}

export interface PemBlock {
  label: string
  der: Uint8Array<ArrayBuffer>
}

/** Every PEM block in the text, in order. Text outside the blocks is ignored. */
export function pemDecodeAll(text: string): PemBlock[] {
  const blocks: PemBlock[] = []
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g
  for (const match of text.matchAll(re)) {
    blocks.push({ label: match[1]!, der: fromBase64(match[2]!.replace(/\s+/g, '')) })
  }
  return blocks
}

/** DER of a single object given as DER or as PEM with one of the accepted labels. */
export function toDer(input: string | Uint8Array, labels: readonly string[]): Uint8Array<ArrayBuffer> {
  if (input instanceof Uint8Array) return bytes(input)
  if (typeof input !== 'string') throw new PkiError('invalid_input', 'Expected PEM text or DER bytes')
  const blocks = pemDecodeAll(input)
  if (blocks.length !== 1 || !labels.includes(blocks[0]!.label)) {
    throw new PkiError('invalid_pem', `Expected exactly one PEM block labelled ${labels.join(' or ')}`)
  }
  return blocks[0]!.der
}

export function certificateToPem(der: Uint8Array): string {
  return pemEncode(der, 'CERTIFICATE')
}

/** Parses one certificate. Refuses trailing data and anything that is not a certificate. */
export function parseCertificate(input: CertificateInput): x509.X509Certificate {
  try {
    return new x509.X509Certificate(toDer(input, ['CERTIFICATE']))
  } catch (error) {
    if (error instanceof PkiError) throw error
    throw new PkiError('invalid_certificate', 'Not a valid X.509 certificate')
  }
}

/** All certificates in a PEM bundle, in order. */
export function parseCertificateBundle(text: string): Uint8Array<ArrayBuffer>[] {
  const blocks = pemDecodeAll(text)
  if (blocks.some((b) => b.label !== 'CERTIFICATE')) throw new PkiError('invalid_pem', 'The bundle may only contain certificates')
  for (const block of blocks) parseCertificate(block.der)
  return blocks.map((b) => b.der)
}

/**
 * A PEM bundle as servers expect it: the leaf, then its issuer, then the rest of the chain up to
 * (and normally including) the root.
 */
export function buildCertificateBundle(leaf: CertificateInput, issuer?: CertificateInput | null, chain: readonly CertificateInput[] = []): string {
  const all = [leaf, ...(issuer ? [issuer] : []), ...chain]
  return all.map((c) => certificateToPem(new Uint8Array(parseCertificate(c).rawData))).join('')
}

export type FingerprintAlgorithm = 'SHA-256' | 'SHA-1'

/** Lowercase hex digest of the DER encoding. */
export async function fingerprint(der: Uint8Array, algorithm: FingerprintAlgorithm = 'SHA-256'): Promise<string> {
  return toHex(await crypto.subtle.digest(algorithm, bytes(der)))
}
