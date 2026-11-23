import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, query, resetState, sentMails, serverOptions } from '../helpers'

describe('rate limits', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('counts sign-in attempts and answers 429 once the limit is used up', async () => {
    const client = new Client()
    // Ten attempts a minute are allowed; wrong codes are refused on their own merits.
    const first = await client.rpc('sign_in_codes.verify', { email: 'a@example.com', code: '000000' })
    expect(first.status).toBe(401)
    expect(first.headers.get('ratelimit-limit')).toBe('10')
    expect(first.headers.get('ratelimit-remaining')).toBe('9')
    for (let i = 1; i < 10; i++) expect((await client.rpc('sign_in_codes.verify', { email: 'a@example.com', code: '000000' })).status).toBe(401)

    const limited = await client.rpc('sign_in_codes.verify', { email: 'a@example.com', code: '000000' })
    expect(limited.status).toBe(429)
    expect(limited.body.error.code).toBe('rate_limited')
    expect(limited.headers.get('retry-after')).toMatch(/^\d+$/)
    expect(limited.headers.get('ratelimit-remaining')).toBe('0')
  })

  it('limits code mails per address without saying so, and code requests per client', async () => {
    const client = new Client()
    // Five mails per address in ten minutes (the setup-less first request makes this address an admin).
    for (let i = 0; i < 5; i++) expect((await client.rpc('sign_in_codes.create', { email: 'one@example.com' })).status).toBe(200)
    const sixth = await client.rpc('sign_in_codes.create', { email: 'one@example.com' })
    // The same answer as before, but no further mail.
    expect(sixth.status).toBe(200)
    expect(sixth.body).toEqual({ data: { sent: true } })
    expect(await sentMails('one@example.com')).toHaveLength(5)
    // Another address is unaffected until the per-client limit of 20 an hour.
    expect((await client.rpc('sign_in_codes.create', { email: 'two@example.com' })).status).toBe(200)
    for (let i = 0; i < 13; i++) await client.rpc('sign_in_codes.create', { email: `x${i}@example.com` })
    const limited = await client.rpc('sign_in_codes.create', { email: 'three@example.com' })
    expect(limited.status).toBe(429)
    expect(limited.body.error.code).toBe('rate_limited')
  })

  it('starts counting again in the next window and keeps counters in Postgres', async () => {
    const client = new Client()
    for (let i = 0; i < 11; i++) await client.rpc('sign_in_codes.verify', { email: 'a@example.com', code: '000000' })
    expect((await client.rpc('sign_in_codes.verify', { email: 'a@example.com', code: '000000' })).status).toBe(429)
    const [row] = await query()`select key, count from rate_limits where key like 'signinVerify:%'`
    expect(row!.count).toBeGreaterThan(10)
    await query()`truncate rate_limits`
    expect((await client.rpc('sign_in_codes.verify', { email: 'a@example.com', code: '000000' })).status).toBe(401)
  })
})
