import type { KeyAlgorithm, Signer } from '@certifly/keyvault'
import { bytes } from './encoding'
import { PkiError } from './errors'

export type { HashAlgorithm, KeyAlgorithm, Signer } from '@certifly/keyvault'

/** WebCrypto parameters for signing with a key of this algorithm. */
export function signingAlgorithm(algorithm: KeyAlgorithm): EcdsaParams & EcKeyAlgorithm | RsaHashedKeyAlgorithm {
  switch (algorithm) {
    case 'ecdsa-p256':
      return { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as EcdsaParams & EcKeyAlgorithm
    case 'ecdsa-p384':
      return { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' } as EcdsaParams & EcKeyAlgorithm
    case 'rsa-2048':
    case 'rsa-3072':
    case 'rsa-4096':
      return {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
        modulusLength: Number(algorithm.slice(4)),
        publicExponent: new Uint8Array([1, 0, 1]),
      }
    default:
      throw new PkiError('unsupported_key', `Unsupported signing algorithm: ${String(algorithm)}`)
  }
}

export interface X509Signing {
  /** Pass as the `crypto` argument of x509's generators. */
  crypto: Crypto
  /** An opaque stand-in for the private key; it holds no key material. */
  signingKey: CryptoKey
  signingAlgorithm: Algorithm
}

function hashName(hash: unknown): string | undefined {
  if (typeof hash === 'string') return hash
  if (hash && typeof hash === 'object' && 'name' in hash) return String((hash as { name: unknown }).name)
  return undefined
}

/**
 * Lets @peculiar/x509 sign with a key it never sees. x509 calls `crypto.subtle.sign(alg, key,
 * tbs)` on the provider it is given; this provider sends that call to the signer when the key
 * is our stand-in and leaves every other operation to the platform's WebCrypto.
 *
 * This is preferred over importing the private key as a CryptoKey for the call: no key object
 * ever reaches library code (so nothing can keep it around), the key is decrypted only inside
 * the signer's own `sign`, and the same path works for keys that cannot be exported at all
 * (PKCS#11, cloud KMS).
 */
export function x509Signing(signer: Signer): X509Signing {
  const algorithm = signingAlgorithm(signer.key_algorithm)
  const keyAlgorithm = 'namedCurve' in algorithm ? { name: algorithm.name, namedCurve: algorithm.namedCurve } : algorithm
  const signingKey = Object.freeze({ type: 'private', extractable: false, algorithm: keyAlgorithm, usages: ['sign'] }) as unknown as CryptoKey
  const platform = globalThis.crypto

  const subtle = new Proxy(platform.subtle, {
    get(target, property) {
      if (property === 'sign') {
        return async (alg: AlgorithmIdentifier & { hash?: unknown }, key: CryptoKey, data: BufferSource) => {
          if (key !== signingKey) return target.sign(alg as AlgorithmIdentifier, key, data)
          const name = typeof alg === 'string' ? alg : alg.name
          const hash = hashName(typeof alg === 'string' ? undefined : alg.hash)
          if (name !== algorithm.name || (hash !== undefined && hash !== signer.hash)) {
            throw new PkiError('signer_mismatch', 'The signer cannot produce the requested signature algorithm')
          }
          const view = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data)
          const signature = await signer.sign(bytes(view))
          return bytes(signature).buffer
        }
      }
      const value = Reflect.get(target, property, target)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })

  const crypto = {
    subtle,
    getRandomValues: platform.getRandomValues.bind(platform),
    randomUUID: platform.randomUUID.bind(platform),
  } as Crypto

  return { crypto, signingKey, signingAlgorithm: algorithm }
}
