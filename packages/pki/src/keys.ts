import type { KeyAlgorithm } from '@certifly/keyvault'
import { bytes, pemEncode } from './encoding'
import { PkiError } from './errors'
import * as x509 from './x509'

export interface PublicKeyDescription {
  type: 'ec' | 'rsa'
  /** `ecdsa-p256`, `ecdsa-p384`, or `rsa-<bits>` (2048 to 8192). */
  key_algorithm: string
  bits: number
  curve?: 'P-256' | 'P-384'
  /** SubjectPublicKeyInfo DER. */
  spki: Uint8Array<ArrayBuffer>
}

const MIN_RSA_BITS = 2048
const MAX_RSA_BITS = 8192

/**
 * Describes a public key and refuses the ones certifly does not accept: RSA below 2048 bits (or
 * above 8192), curves other than P-256 and P-384, and every other key type.
 */
export async function describePublicKey(spki: Uint8Array): Promise<PublicKeyDescription> {
  let key: x509.PublicKey
  try {
    key = new x509.PublicKey(bytes(spki))
  } catch {
    throw new PkiError('unsupported_key', 'Not a valid public key')
  }
  const algorithm = key.algorithm as Algorithm & { namedCurve?: string; modulusLength?: number }
  let description: PublicKeyDescription
  let importParams: EcKeyImportParams | RsaHashedImportParams
  if (algorithm.name === 'ECDSA' && (algorithm.namedCurve === 'P-256' || algorithm.namedCurve === 'P-384')) {
    const curve = algorithm.namedCurve
    description = { type: 'ec', key_algorithm: curve === 'P-256' ? 'ecdsa-p256' : 'ecdsa-p384', bits: curve === 'P-256' ? 256 : 384, curve, spki: bytes(spki) }
    importParams = { name: 'ECDSA', namedCurve: curve }
  } else if (algorithm.name === 'RSASSA-PKCS1-v1_5' && typeof algorithm.modulusLength === 'number') {
    const bits = algorithm.modulusLength
    if (bits < MIN_RSA_BITS || bits > MAX_RSA_BITS) throw new PkiError('unsupported_key', `RSA keys must be ${MIN_RSA_BITS} to ${MAX_RSA_BITS} bits, not ${bits}`)
    description = { type: 'rsa', key_algorithm: `rsa-${bits}`, bits, spki: bytes(spki) }
    importParams = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
  } else {
    const what = algorithm.namedCurve ? `${algorithm.name} ${algorithm.namedCurve}` : algorithm.name
    throw new PkiError('unsupported_key', `Unsupported key type: ${what}. Use ECDSA P-256/P-384 or RSA 2048+.`)
  }
  // WebCrypto rejects malformed keys, e.g. an EC point that is not on the curve.
  try {
    await crypto.subtle.importKey('spki', bytes(spki), importParams, true, ['verify'])
  } catch {
    throw new PkiError('unsupported_key', 'The public key is malformed')
  }
  return description
}

/**
 * A key pair for a leaf certificate whose private key is handed to the requester once (PEM or
 * PKCS#12) and then dropped. Extractable on purpose; never use this for CA keys, which are
 * generated inside the keyvault.
 */
export async function generateLeafKeyPair(algorithm: KeyAlgorithm): Promise<CryptoKeyPair> {
  const params: EcKeyGenParams | RsaHashedKeyGenParams =
    algorithm === 'ecdsa-p256' || algorithm === 'ecdsa-p384'
      ? { name: 'ECDSA', namedCurve: algorithm === 'ecdsa-p256' ? 'P-256' : 'P-384' }
      : { name: 'RSASSA-PKCS1-v1_5', modulusLength: Number(String(algorithm).slice(4)), publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
  if (!['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'].includes(algorithm)) {
    throw new PkiError('unsupported_key', `Unsupported key algorithm: ${String(algorithm)}`)
  }
  return crypto.subtle.generateKey(params, true, ['sign', 'verify'])
}

export async function publicKeySpki(publicKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
}

/** PKCS#8 PEM of a generated leaf key, for the one-time download. */
export async function leafPrivateKeyToPem(privateKey: CryptoKey): Promise<string> {
  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey))
  try {
    return pemEncode(der, 'PRIVATE KEY')
  } finally {
    der.fill(0)
  }
}
