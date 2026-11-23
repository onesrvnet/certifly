import { describe, expect, it } from 'vitest'
import { decryptSecret, encryptSecret, randomCode, randomToken, safeEqualHex, safeEqualString, sha256 } from '../src/crypto'

describe('random values', () => {
  it('makes URL-safe tokens that differ every time', () => {
    const a = randomToken()
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(randomToken()).not.toBe(a)
  })

  it('makes six digit codes, keeping leading zeros', () => {
    for (let i = 0; i < 200; i++) expect(randomCode()).toMatch(/^\d{6}$/)
  })
})

describe('sha256', () => {
  it('hashes to lowercase hex', () => {
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})

describe('constant-time comparison', () => {
  it('compares hex digests', () => {
    expect(safeEqualHex(sha256('a'), sha256('a'))).toBe(true)
    expect(safeEqualHex(sha256('a'), sha256('b'))).toBe(false)
    expect(safeEqualHex(sha256('a'), 'abcd')).toBe(false)
  })

  it('compares strings of any length', () => {
    expect(safeEqualString('s3cret', 's3cret')).toBe(true)
    expect(safeEqualString('s3cret', 's3cret ')).toBe(false)
    expect(safeEqualString('', 'x')).toBe(false)
    expect(safeEqualString('', '')).toBe(true)
  })
})

describe('stored secrets', () => {
  const key = 'a'.repeat(64)

  it('round-trips a secret', () => {
    const stored = encryptSecret(key, 'hunter2 ü')
    expect(stored.startsWith('v1.')).toBe(true)
    expect(stored).not.toContain('hunter2')
    expect(decryptSecret(key, stored)).toBe('hunter2 ü')
  })

  it('encrypts the same text differently each time', () => {
    expect(encryptSecret(key, 'x')).not.toBe(encryptSecret(key, 'x'))
  })

  it('refuses another key, a changed value and unknown formats', () => {
    const stored = encryptSecret(key, 'x')
    expect(() => decryptSecret('b'.repeat(64), stored)).toThrow()
    const [v, iv, tag, data] = stored.split('.')
    const flipped = Buffer.from(data!, 'base64url')
    flipped[0] = flipped[0]! ^ 1
    expect(() => decryptSecret(key, [v, iv, tag, flipped.toString('base64url')].join('.'))).toThrow()
    expect(() => decryptSecret(key, 'v2.a.b.c')).toThrow('Unknown secret format')
    expect(() => decryptSecret(key, 'garbage')).toThrow('Unknown secret format')
  })
})
