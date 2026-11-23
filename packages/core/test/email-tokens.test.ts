import { describe, expect, it } from 'vitest'
import { checkCode, MAX_CODE_ATTEMPTS, normalizeEmail } from '../src/auth/email-tokens'
import type { Context } from '../src/context'
import { emailCodeHash, sha256 } from '../src/crypto'
import { AuthenticationError, ValidationError } from '../src/errors'

describe('normalizeEmail', () => {
  it('trims and lowercases', () => {
    expect(normalizeEmail('  Ann@Example.COM ')).toBe('ann@example.com')
  })

  it('refuses things that are not an address', () => {
    for (const bad of ['', 'ann', 'ann@', '@example.com', 'ann@example', 'a b@example.com']) {
      expect(() => normalizeEmail(bad)).toThrow(ValidationError)
    }
  })
})

/**
 * A database that records each update and its filter, and answers the n-th update's
 * `returning()` with `answers[n]`.
 */
function fakeContext(answers: unknown[][]) {
  const updates: { set: Record<string, unknown>; where: unknown }[] = []
  const db = {
    update: () => ({
      set: (values: Record<string, unknown>) => ({
        where: (where: unknown) => {
          const n = updates.push({ set: values, where }) - 1
          return Object.assign(Promise.resolve(), { returning: async () => answers[n] ?? [] })
        },
      }),
    }),
  }
  return { ctx: { db, secret_key: SECRET } as unknown as Context, updates }
}

const SECRET = 'test-secret-key-test-secret-key-0000'
const hash = emailCodeHash(SECRET, 't1', '123456')
const consumedRow = { id: 't1', email: 'ann@example.com', code_hash: hash, attempts: 1, consumed_at: new Date() }
const invalid = () => new AuthenticationError('invalid', 'invalid_code')

describe('emailCodeHash', () => {
  it('depends on the secret key and the token, so codes cannot be looked up from the table alone', () => {
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
    expect(hash).toBe(emailCodeHash(SECRET, 't1', '123456'))
    expect(hash).not.toBe(emailCodeHash(`${SECRET}x`, 't1', '123456'))
    expect(hash).not.toBe(emailCodeHash(SECRET, 't2', '123456'))
    expect(hash).not.toBe(sha256('123456'))
  })
})

describe('checkCode', () => {
  it('claims an attempt, then consumes the token when the code is right, ignoring spaces around it', async () => {
    const { ctx, updates } = fakeContext([[{ code_hash: hash, attempts: 1 }], [consumedRow]])
    const consumed = await checkCode(ctx, 't1', ' 123456 ', invalid)
    expect(consumed.id).toBe('t1')
    expect(updates).toHaveLength(2)
    expect(updates[0]!.set).toHaveProperty('attempts')
    expect(updates[0]!.set).not.toHaveProperty('consumed_at')
    expect(updates[1]!.set).toHaveProperty('consumed_at')
  })

  it('refuses without comparing when no attempt could be claimed', async () => {
    const { ctx, updates } = fakeContext([[]])
    await expect(checkCode(ctx, 't1', '123456', invalid)).rejects.toMatchObject({ code: 'invalid_code' })
    expect(updates).toHaveLength(1)
  })

  it('refuses a wrong code and leaves the token usable while attempts remain', async () => {
    const { ctx, updates } = fakeContext([[{ code_hash: hash, attempts: 2 }]])
    await expect(checkCode(ctx, 't1', '000000', invalid)).rejects.toMatchObject({ code: 'invalid_code' })
    expect(updates).toHaveLength(1)
  })

  it('burns the token on a wrong code that uses up the last attempt, never clearing consumed_at', async () => {
    const { ctx, updates } = fakeContext([[{ code_hash: hash, attempts: MAX_CODE_ATTEMPTS }]])
    await expect(checkCode(ctx, 't1', '000000', invalid)).rejects.toMatchObject({ code: 'invalid_code' })
    expect(updates).toHaveLength(2)
    expect(updates[1]!.set.consumed_at).not.toBeNull()
    expect(updates[1]!.set.consumed_at).not.toBeInstanceOf(Date)
  })

  it('refuses a right code when the token was consumed in the meantime', async () => {
    const { ctx } = fakeContext([[{ code_hash: hash, attempts: 1 }], []])
    await expect(checkCode(ctx, 't1', '123456', invalid)).rejects.toMatchObject({ code: 'invalid_code' })
  })

  it('allows a handful of attempts', () => {
    expect(MAX_CODE_ATTEMPTS).toBe(5)
  })
})
