import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, query, resetState, serverOptions } from '../helpers'
import { SoftwareAuthenticator } from '../support/authenticator'

const SETUP_TOKEN = 'setup-token-for-tests-0123456789'

/** A production instance without SMTP but with a setup token: the token holder creates the first admin. */
describe('first admin by setup token, without email', async () => {
  await setup({ ...serverOptions, env: { NODE_ENV: 'production', MAIL_OUTBOX_DIR: '', SMTP_URL: '', SETUP_TOKEN } })
  beforeEach(resetState)

  const origin = () => process.env.URL!
  const create = (client: Client, body: Record<string, unknown>) => client.rpc('setup_accounts.create', body)

  it('tells the sign-in page that setup goes by token, and stops once someone has a passkey', async () => {
    expect((await new Client().rpc('auth_config.get')).body.data.setup_method).toBe('token')

    const admin = new Client()
    expect((await create(admin, { setup_token: SETUP_TOKEN, email: 'Admin@Example.com', name: 'Ada' })).status).toBe(200)
    // Still open for getting back in while the admin has no passkey.
    expect((await new Client().rpc('auth_config.get')).body.data.setup_method).toBe('token')

    const device = new SoftwareAuthenticator(new URL(origin()).hostname, origin())
    const options = (await admin.rpc('passkey_registrations.create')).body.data
    expect((await admin.rpc('passkey_registrations.verify', { response: device.register(options), name: 'Laptop' })).status).toBe(200)
    expect((await new Client().rpc('auth_config.get')).body.data.setup_method).toBeNull()
  })

  it('creates the admin and signs them in, who can then use the instance', async () => {
    const admin = new Client()
    const created = await create(admin, { setup_token: SETUP_TOKEN, email: 'admin@example.com' })
    expect(created.status).toBe(200)
    const session = (await admin.rpc('sessions.get')).body.data
    expect(session.user).toMatchObject({ email: 'admin@example.com', role: 'admin' })
    // Nothing is held back until a passkey exists.
    expect((await admin.rpc('events.list')).status).toBe(200)
    const [event] = await query()`select data from events where name = 'users.create'`
    expect(event?.data).toMatchObject({ method: 'setup_token' })
    expect(JSON.stringify(event?.data)).not.toContain(SETUP_TOKEN)
  })

  it('refuses a wrong or missing token, and creates nobody', async () => {
    const wrong = await create(new Client(), { setup_token: 'not-the-token', email: 'admin@example.com' })
    expect(wrong.status).toBe(403)
    expect(wrong.body.error.code).toBe('setup_token_invalid')
    expect((await create(new Client(), { setup_token: '', email: 'admin@example.com' })).status).toBe(400)
    const [{ n }] = await query()`select count(*)::int as n from users`
    expect(n).toBe(0)
  })

  it('lets the token get back into the same account until it has a passkey, but never a second one', async () => {
    await create(new Client(), { setup_token: SETUP_TOKEN, email: 'admin@example.com' })
    const again = new Client()
    expect((await create(again, { setup_token: SETUP_TOKEN, email: 'admin@example.com' })).status).toBe(200)
    expect((await again.rpc('sessions.get')).body.data.user.email).toBe('admin@example.com')

    const other = await create(new Client(), { setup_token: SETUP_TOKEN, email: 'someone@example.com' })
    expect(other.status).toBe(409)
    expect(other.body.error.code).toBe('setup_email_mismatch')
    const [{ n }] = await query()`select count(*)::int as n from users`
    expect(n).toBe(1)
  })

  it('closes for good once the admin has a passkey, with the same answer as a wrong token', async () => {
    const admin = new Client()
    await create(admin, { setup_token: SETUP_TOKEN, email: 'admin@example.com' })
    const device = new SoftwareAuthenticator(new URL(origin()).hostname, origin())
    const options = (await admin.rpc('passkey_registrations.create')).body.data
    await admin.rpc('passkey_registrations.verify', { response: device.register(options) })

    const closed = await create(new Client(), { setup_token: SETUP_TOKEN, email: 'admin@example.com' })
    expect(closed.status).toBe(403)
    expect(closed.body.error.code).toBe('setup_token_invalid')
  })

  it('makes only one admin when two setups race', async () => {
    const results = await Promise.all([
      create(new Client(), { setup_token: SETUP_TOKEN, email: 'admin@example.com' }),
      create(new Client(), { setup_token: SETUP_TOKEN, email: 'other@example.com' }),
    ])
    expect(results.filter((r) => r.status === 200)).toHaveLength(1)
    const [{ n }] = await query()`select count(*)::int as n from users`
    expect(n).toBe(1)
  })
})
