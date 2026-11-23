import { setup } from '@nuxt/test-utils/e2e'
import { createHash } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, latestSigninMail, query, resetState, sentMails, serverOptions, setupAdmin } from '../helpers'

/**
 * Email codes and links under pressure. The per-client limits are off here, so what is
 * tested is core's own attempt limit and per-address budget, not the limit in front of it.
 */
describe('email codes', async () => {
  await setup({ ...serverOptions, env: { RATE_LIMITS_DISABLED: 'true' } })
  beforeEach(resetState)

  const EMAIL = 'admin@example.com'
  const wrongFor = (code: string) => (code === '000000' ? '111111' : '000000')
  const latestToken = async () => (await query()`select attempts, consumed_at from email_tokens order by created_at desc limit 1`)[0]!

  /** An instance with an admin, and a fresh code (and link) for them. */
  async function freshCode() {
    await setupAdmin()
    await new Client().rpc('sign_in_codes.create', { email: EMAIL })
    return latestSigninMail(EMAIL)
  }

  it('keeps to five attempts when ten wrong guesses and the right one arrive at once', async () => {
    const { code } = await freshCode()
    const guesses = [...Array.from({ length: 10 }, () => wrongFor(code)), code]
    const results = await Promise.all(guesses.map((guess) => new Client().rpc('sign_in_codes.verify', { email: EMAIL, code: guess })))
    expect(results.every((r) => r.status === 200 || r.status === 401)).toBe(true)
    expect(results.filter((r) => r.status === 200).length).toBeLessThanOrEqual(1)
    const token = await latestToken()
    expect(token.attempts).toBeLessThanOrEqual(5)
    // Either the right code won or the token was burned; it is used up both ways.
    expect(token.consumed_at).not.toBeNull()
    expect((await new Client().rpc('sign_in_codes.verify', { email: EMAIL, code })).status).toBe(401)
  })

  it('burns the code and the link after five wrong guesses, however many arrive at once', async () => {
    const { code, token } = await freshCode()
    const results = await Promise.all(Array.from({ length: 10 }, () => new Client().rpc('sign_in_codes.verify', { email: EMAIL, code: wrongFor(code) })))
    expect(results.map((r) => r.status)).toEqual(Array(10).fill(401))
    expect(await latestToken()).toMatchObject({ attempts: 5, consumed_at: expect.any(Date) })
    expect((await new Client().rpc('sign_in_codes.verify', { email: EMAIL, code })).body.error.code).toBe('invalid_code')
    expect((await new Client().rpc('sign_in_codes.verify', { token })).body.error.code).toBe('invalid_token')
  })

  it('does not bring a used code back with a wrong guess afterwards', async () => {
    const { code, token } = await freshCode()
    expect((await new Client().rpc('sign_in_codes.verify', { email: EMAIL, code })).status).toBe(200)
    const used = await latestToken()
    expect((await new Client().rpc('sign_in_codes.verify', { email: EMAIL, code: wrongFor(code) })).status).toBe(401)
    expect(await latestToken()).toEqual(used)
    expect((await new Client().rpc('sign_in_codes.verify', { email: EMAIL, code })).status).toBe(401)
    expect((await new Client().rpc('sign_in_codes.verify', { token })).status).toBe(401)
  })

  it('stores codes keyed with the server secret, not as a hash anyone could reverse', async () => {
    const { code } = await freshCode()
    const [row] = await query()`select code_hash from email_tokens order by created_at desc limit 1`
    expect(row!.code_hash).not.toBe(createHash('sha256').update(code).digest('hex'))
  })

  it('answers the same for a known and an unknown address once their budget is used up', async () => {
    await setupAdmin()
    const answers = async (email: string) => {
      const out: unknown[] = []
      for (let i = 0; i < 7; i++) {
        const { status, body } = await new Client().rpc('sign_in_codes.create', { email })
        out.push({ status, body })
      }
      return out
    }
    const known = await answers(EMAIL)
    const unknown = await answers('stranger@example.com')
    expect(known).toEqual(unknown)
    expect(new Set(known.map((a) => JSON.stringify(a)))).toEqual(new Set([JSON.stringify({ status: 200, body: { data: { sent: true } } })]))
    // Five mails in the window (the setup mail was one of them), then silence; nothing for the stranger.
    expect(await sentMails(EMAIL)).toHaveLength(5)
    expect(await sentMails('stranger@example.com')).toHaveLength(0)
    // The counters do not keep the addresses people typed in.
    const keys = (await query()`select key from rate_limits`).map((r) => r.key as string)
    expect(keys.some((k) => k.includes('stranger') || k.includes('admin@'))).toBe(false)
  })

  it('keeps the last code sent working for its owner while a stranger uses up the budget', async () => {
    await setupAdmin()
    for (let i = 0; i < 10; i++) await new Client().rpc('sign_in_codes.create', { email: EMAIL })
    expect(await sentMails(EMAIL)).toHaveLength(5)
    const { code } = await latestSigninMail(EMAIL)
    expect((await new Client().rpc('sign_in_codes.verify', { email: EMAIL, code })).status).toBe(200)
  })

  it('keeps re-authentication mails apart, so others asking for sign-in codes cannot use them up', async () => {
    const admin = await setupAdmin()
    for (let i = 0; i < 6; i++) await new Client().rpc('sign_in_codes.create', { email: EMAIL })
    const before = (await sentMails(EMAIL)).length
    expect((await admin.rpc('reauthentications.create', { method: 'email' })).status).toBe(200)
    expect(await sentMails(EMAIL)).toHaveLength(before + 1)
  })
})
