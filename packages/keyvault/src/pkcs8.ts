import { bytesEqual, copy, toBase64Url } from './bytes'
import { KeyvaultError } from './errors'
import type { HashAlgorithm, KeyAlgorithm } from './types'

// A tiny DER reader: enough to tell which algorithm a PKCS#8 key is and to copy out its public
// half, without handing the private parts to a general-purpose parser or a JWK string.

interface Tlv {
  tag: number
  /** Where the header begins. */
  offset: number
  /** Where the content begins and ends. */
  start: number
  end: number
}

function bad(): never {
  throw new KeyvaultError('unsupported_algorithm', 'The private key is not a supported PKCS#8 key')
}

function readTlv(der: Uint8Array, offset: number, limit = der.byteLength): Tlv {
  if (offset + 2 > limit) bad()
  const tag = der[offset]!
  let length = der[offset + 1]!
  let start = offset + 2
  if (length & 0x80) {
    const count = length & 0x7f
    if (count === 0 || count > 4 || start + count > limit) bad()
    length = 0
    for (let i = 0; i < count; i++) length = length * 256 + der[start + i]!
    start += count
  }
  const end = start + length
  if (end > limit) bad()
  return { tag, offset, start, end }
}

function children(der: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = []
  for (let offset = parent.start; offset < parent.end; ) {
    const tlv = readTlv(der, offset, parent.end)
    out.push(tlv)
    offset = tlv.end
  }
  return out
}

const SEQUENCE = 0x30
const OCTET_STRING = 0x04
const BIT_STRING = 0x03
const INTEGER = 0x02

// DER of the AlgorithmIdentifier values we accept (RFC 5480 §2.1.1, RFC 8017 §A.1).
const RSA_ALG_ID = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
const RSA_ALG_ID_NO_NULL = new Uint8Array([0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
const P256_ALG_ID = new Uint8Array([0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
// RFC 8410 §3: id-Ed25519 has no parameters.
const ED25519_ALG_ID = new Uint8Array([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70])
const P384_ALG_ID = new Uint8Array([0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22])

export type KeyFamily = { kind: 'ec'; curve: 'P-256' | 'P-384' } | { kind: 'rsa' } | { kind: 'ed25519' }

interface Parsed {
  family: KeyFamily
  /** The inner key structure (ECPrivateKey or RSAPrivateKey). */
  inner: Tlv
}

function parse(der: Uint8Array): Parsed {
  const outer = readTlv(der, 0)
  if (outer.tag !== SEQUENCE || outer.end !== der.byteLength) bad()
  const [version, algId, key] = children(der, outer)
  if (!version || version.tag !== INTEGER || !algId || algId.tag !== SEQUENCE || !key || key.tag !== OCTET_STRING) bad()
  const algBytes = der.subarray(algId.offset, algId.end)
  let family: KeyFamily
  if (bytesEqual(algBytes, RSA_ALG_ID) || bytesEqual(algBytes, RSA_ALG_ID_NO_NULL)) family = { kind: 'rsa' }
  else if (bytesEqual(algBytes, P256_ALG_ID)) family = { kind: 'ec', curve: 'P-256' }
  else if (bytesEqual(algBytes, P384_ALG_ID)) family = { kind: 'ec', curve: 'P-384' }
  else if (bytesEqual(algBytes, ED25519_ALG_ID)) family = { kind: 'ed25519' }
  else bad()
  const inner = readTlv(der, key.start, key.end)
  if (inner.end !== key.end) bad()
  // Ed25519 wraps its 32-byte seed in an OCTET STRING (RFC 8410 §7); the others hold a SEQUENCE.
  if (family.kind === 'ed25519' ? inner.tag !== OCTET_STRING || inner.end - inner.start !== 32 : inner.tag !== SEQUENCE) bad()
  return { family, inner }
}

export function keyFamily(pkcs8: Uint8Array): KeyFamily {
  return parse(pkcs8).family
}

export function webCryptoImportParams(family: KeyFamily, hash: HashAlgorithm): EcKeyImportParams | RsaHashedImportParams | Algorithm {
  if (family.kind === 'ed25519') return { name: 'Ed25519' }
  return family.kind === 'ec' ? { name: 'ECDSA', namedCurve: family.curve } : { name: 'RSASSA-PKCS1-v1_5', hash }
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0
  while (i < bytes.byteLength - 1 && bytes[i] === 0) i++
  return bytes.subarray(i)
}

/** Builds the SubjectPublicKeyInfo DER from the public half of a PKCS#8 key. */
export async function publicKeyFromPkcs8(pkcs8: Uint8Array): Promise<{ spki: Uint8Array<ArrayBuffer>; algorithm: KeyAlgorithm }> {
  const { family, inner } = parse(pkcs8)
  if (family.kind === 'ed25519') {
    // The seed does not carry the public key, so derive it: import extractable, read the JWK's
    // public half, and let both CryptoKeys go.
    const key = await crypto.subtle.importKey('pkcs8', copy(pkcs8), { name: 'Ed25519' }, true, ['sign'])
    const jwk = await crypto.subtle.exportKey('jwk', key)
    const raw = Uint8Array.from(atob(jwk.x!.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
    const pub = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, true, ['verify'])
    return { spki: new Uint8Array(await crypto.subtle.exportKey('spki', pub)), algorithm: 'ed25519' }
  }
  const fields = children(pkcs8, inner)
  let publicKey: CryptoKey
  if (family.kind === 'ec') {
    // ECPrivateKey (RFC 5915 §3): the public point sits in the optional [1] field.
    const tagged = fields.find((f) => f.tag === 0xa1)
    if (!tagged) bad()
    const bits = readTlv(pkcs8, tagged.start, tagged.end)
    if (bits.tag !== BIT_STRING || pkcs8[bits.start] !== 0) bad()
    const point = copy(pkcs8.subarray(bits.start + 1, bits.end))
    publicKey = await crypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: family.curve }, true, ['verify'])
  } else {
    // RSAPrivateKey (RFC 8017 §A.1.2): version, modulus, publicExponent, then private fields.
    const [, modulus, exponent] = fields
    if (!modulus || modulus.tag !== INTEGER || !exponent || exponent.tag !== INTEGER) bad()
    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: toBase64Url(stripLeadingZeros(pkcs8.subarray(modulus.start, modulus.end))),
      e: toBase64Url(stripLeadingZeros(pkcs8.subarray(exponent.start, exponent.end))),
    }
    publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify'])
  }
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
  return { spki, algorithm: algorithmOf(family, publicKey.algorithm) }
}

/** Our algorithm name for an imported WebCrypto key of this family. */
export function algorithmOf(family: KeyFamily, keyAlgorithm: globalThis.KeyAlgorithm): KeyAlgorithm {
  if (family.kind === 'ed25519') return 'ed25519'
  if (family.kind === 'ec') return family.curve === 'P-256' ? 'ecdsa-p256' : 'ecdsa-p384'
  const bits = (keyAlgorithm as RsaHashedKeyAlgorithm).modulusLength
  if (bits === 2048) return 'rsa-2048'
  if (bits === 3072) return 'rsa-3072'
  if (bits === 4096) return 'rsa-4096'
  throw new KeyvaultError('unsupported_algorithm', 'Only 2048, 3072 and 4096 bit RSA keys are supported')
}
