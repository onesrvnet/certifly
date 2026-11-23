/**
 * Key algorithms certifly signs with. The default hash is fixed per algorithm (see `hashFor`).
 * Ed25519 is for SSH certificate authorities only; X.509 flows refuse it.
 */
export type KeyAlgorithm = 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096' | 'ed25519'

/** `none` is Ed25519, which hashes internally. SHA-512 is only for RSA keys signing SSH certificates. */
export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512' | 'none'

export const KEY_ALGORITHMS: readonly KeyAlgorithm[] = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096', 'ed25519']

/** The envelope scheme: AES-256-GCM for the key under its DEK and for the DEK under the KEK. */
export const ENVELOPE_ALG = 'aes-256-gcm-envelope-v1'

/**
 * An encrypted private key as stored in a database row. The plaintext is PKCS#8 DER; it is only
 * ever decrypted inside this package. Both layers are bound to the caller's binding string as AAD.
 */
export interface EncryptedKeyRecord {
  alg: string
  /** Which master key (KEK) wrapped the DEK; see `kekId`. */
  kek_id: string
  wrapped_dek: Uint8Array
  dek_iv: Uint8Array
  dek_tag: Uint8Array
  ciphertext: Uint8Array
  iv: Uint8Array
  tag: Uint8Array
}

export interface SignerOptions {
  /** RSA keys only: SHA-512 for `rsa-sha2-512` SSH signatures. Defaults to `hashFor(algorithm)`. */
  hash?: HashAlgorithm
}

export interface GeneratedKey {
  record: EncryptedKeyRecord
  algorithm: KeyAlgorithm
  /** SubjectPublicKeyInfo DER. */
  public_key_spki: Uint8Array<ArrayBuffer>
}

/**
 * Signs with one stored key. It holds only the encrypted record: every `sign` call decrypts the
 * key, signs and drops it again, so a signer can be passed to certificate builders safely.
 */
export interface Signer {
  readonly key_algorithm: KeyAlgorithm
  readonly hash: HashAlgorithm
  /** Signature in WebCrypto format: PKCS#1 v1.5 for RSA, r || s (IEEE P1363) for ECDSA. */
  sign(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>>
}

/**
 * A backend that holds CA private keys. Private key bytes never leave it, and there is
 * deliberately no way to export one.
 */
export interface KeyProvider {
  generate(algorithm: KeyAlgorithm, binding: string): Promise<GeneratedKey>
  /** Signature in WebCrypto format. `hash` must be one the key's algorithm allows (see `allowedHashes`). */
  sign(record: EncryptedKeyRecord, binding: string, data: Uint8Array, hash: HashAlgorithm): Promise<Uint8Array<ArrayBuffer>>
  /** SubjectPublicKeyInfo DER of the stored key. */
  publicKey(record: EncryptedKeyRecord, binding: string): Promise<Uint8Array<ArrayBuffer>>
  /**
   * A signer for certificate builders. `algorithm` is what the caller has on record for the key;
   * each signature checks it against the decrypted key, so a swapped column is caught.
   */
  signer(record: EncryptedKeyRecord, binding: string, algorithm: KeyAlgorithm, options?: SignerOptions): Signer
  /**
   * Stores an existing PKCS#8 key. Only two callers: an administrator importing an SSH CA key
   * (a step-up action) and test fixtures. CA keys are otherwise generated inside the provider.
   */
  importPkcs8(pkcs8: Uint8Array, binding: string): Promise<GeneratedKey>
}
