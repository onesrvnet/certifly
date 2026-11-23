import { KeyvaultError } from './errors'
import type { KeyFamily } from './pkcs8'
import { KEY_ALGORITHMS, type HashAlgorithm, type KeyAlgorithm } from './types'

/** SHA-384 for P-384 (matching strength), none for Ed25519, SHA-256 for everything else. */
export function hashFor(algorithm: KeyAlgorithm): HashAlgorithm {
  if (algorithm === 'ed25519') return 'none'
  return algorithm === 'ecdsa-p384' ? 'SHA-384' : 'SHA-256'
}

/** The hashes a key may sign with: its default, plus SHA-512 for RSA (SSH `rsa-sha2-512`). */
export function allowedHashes(algorithm: KeyAlgorithm): HashAlgorithm[] {
  return algorithm.startsWith('rsa-') ? ['SHA-256', 'SHA-512'] : [hashFor(algorithm)]
}

export function isKeyAlgorithm(value: unknown): value is KeyAlgorithm {
  return typeof value === 'string' && (KEY_ALGORITHMS as readonly string[]).includes(value)
}

export function assertKeyAlgorithm(value: unknown): asserts value is KeyAlgorithm {
  if (!isKeyAlgorithm(value)) throw new KeyvaultError('unsupported_algorithm', 'Unsupported key algorithm')
}

export function familyOf(algorithm: KeyAlgorithm): KeyFamily {
  if (algorithm === 'ed25519') return { kind: 'ed25519' }
  if (algorithm === 'ecdsa-p256') return { kind: 'ec', curve: 'P-256' }
  if (algorithm === 'ecdsa-p384') return { kind: 'ec', curve: 'P-384' }
  return { kind: 'rsa' }
}

export function generateParams(algorithm: KeyAlgorithm): EcKeyGenParams | RsaHashedKeyGenParams | Algorithm {
  const family = familyOf(algorithm)
  if (family.kind === 'ed25519') return { name: 'Ed25519' }
  if (family.kind === 'ec') return { name: 'ECDSA', namedCurve: family.curve }
  return {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: Number(algorithm.slice(4)),
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: hashFor(algorithm),
  }
}

export function signParams(algorithm: KeyAlgorithm): EcdsaParams | Algorithm {
  const kind = familyOf(algorithm).kind
  if (kind === 'ed25519') return { name: 'Ed25519' }
  return kind === 'ec' ? { name: 'ECDSA', hash: hashFor(algorithm) } : { name: 'RSASSA-PKCS1-v1_5' }
}
