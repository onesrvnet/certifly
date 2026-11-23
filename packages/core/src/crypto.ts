import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, randomInt, timingSafeEqual } from 'node:crypto'

/** URL-safe random token with 256 bits of entropy. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

/** Zero-padded six digit numeric code. */
export function randomCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0')
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

/** Constant-time comparison of two hex digests. */
export function safeEqualHex(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex')
  const right = Buffer.from(b, 'hex')
  return left.length === right.length && timingSafeEqual(left, right)
}

/**
 * Constant-time comparison of two strings, e.g. a setup token against the configured one.
 * Both are hashed first, so a different length does not show in the timing either.
 */
export function safeEqualString(a: string, b: string): boolean {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest())
}

/**
 * Hash of a one-time email code, keyed with the server's SECRET_KEY and bound to its token.
 * A six-digit code has so few values that a plain hash is reversed instantly by anyone who
 * can read the table; without the key it cannot be checked offline at all.
 */
export function emailCodeHash(secret_key: string, token_id: string, code: string): string {
  const key = Buffer.from(hkdfSync('sha256', secret_key, '', 'certifly:email-codes', 32))
  return createHmac('sha256', key).update(`${token_id}:${code}`).digest('hex')
}

/** AES-256-GCM key for secrets stored in the database, derived from the server's SECRET_KEY. */
function secretsKey(secret_key: string) {
  return Buffer.from(hkdfSync('sha256', secret_key, '', 'certifly:stored-secrets', 32))
}

/** Encrypt a secret (e.g. an OIDC client secret) for storage: `v1.<iv>.<tag>.<data>`. */
export function encryptSecret(secret_key: string, plaintext: string): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', secretsKey(secret_key), iv)
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  return ['v1', iv, cipher.getAuthTag(), data].map((part) => (typeof part === 'string' ? part : part.toString('base64url'))).join('.')
}

/** Decrypt a value from `encryptSecret`. Throws when it was encrypted with another key. */
export function decryptSecret(secret_key: string, stored: string): string {
  const [version, iv, tag, data] = stored.split('.')
  if (version !== 'v1' || !iv || !tag || !data) throw new Error('Unknown secret format')
  const decipher = createDecipheriv('aes-256-gcm', secretsKey(secret_key), Buffer.from(iv, 'base64url'))
  decipher.setAuthTag(Buffer.from(tag, 'base64url'))
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8')
}
