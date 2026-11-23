import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, query, resetState, serverOptions } from '../helpers'
import { SoftwareAuthenticator } from '../support/authenticator'

/** A production instance without SMTP_URL: nothing can be mailed. */
describe('production without SMTP', async () => {
  await setup({ ...serverOptions, env: { NODE_ENV: 'production', MAIL_OUTBOX_DIR: '', SMTP_URL: '' } })
  beforeEach(resetState)

  const origin = () => process.env.URL!

  /** An admin who signs in with a passkey, the one way in besides the identity provider. */
  async function passkeyAdmin() {
    const device = new SoftwareAuthenticator(new URL(origin()).hostname, origin())
    const [user] = await query()`insert into users (email, name, role) values ('admin@example.com', 'admin', 'admin') returning id`
    await query()`insert into passkeys (user_id, credential_id, public_key, name)
      values (${user!.id}, ${device.credentialIdBase64url}, ${device.cosePublicKey()}, 'Laptop')`
    const client = new Client()
    const options = (await client.rpc('passkey_sign_ins.create')).body.data
    expect((await client.rpc('passkey_sign_ins.verify', { response: device.authenticate(options) })).status).toBe(200)
    return client
  }

  it('tells the sign-in page that email is off', async () => {
    const { body } = await new Client().rpc('auth_config.get')
    expect(body.data).toMatchObject({ email_enabled: false })
  })

  it('refuses email sign-in and email re-authentication', async () => {
    const admin = await passkeyAdmin()
    const requested = await new Client().rpc('sign_in_codes.create', { email: 'admin@example.com' })
    expect(requested.status).toBe(403)
    expect(requested.body.error.code).toBe('email_disabled')
    expect((await new Client().rpc('sign_in_codes.verify', { email: 'admin@example.com', code: '123456' })).body.error.code).toBe('email_disabled')
    expect((await new Client().rpc('sign_in_codes.verify', { token: 'anything' })).body.error.code).toBe('email_disabled')
    expect((await admin.rpc('reauthentications.create', { method: 'email' })).body.error.code).toBe('email_disabled')
    const [{ n }] = await query()`select count(*)::int as n from email_tokens`
    expect(n).toBe(0)
  })

  it('hands the admin the invite link once instead of mailing it, and the link works', async () => {
    const admin = await passkeyAdmin()
    const created = await admin.rpc('invites.create', { email: 'ann@example.com', role: 'operator' })
    expect(created.status).toBe(200)
    expect(created.body.data.link).toMatch(/\/invite\?token=[\w-]+$/)
    // Nothing was queued: there is no mail to send.
    const [queue] = await query()`select to_regclass('pgboss.job') as name`
    if (queue?.name) expect((await query()`select 1 from pgboss.job where name = 'mail.send'`).length).toBe(0)
    // The list never shows the link again.
    expect(JSON.stringify((await admin.rpc('invites.list')).body)).not.toContain('token')

    const token = new URL(created.body.data.link).searchParams.get('token')!
    const ann = new Client()
    expect((await ann.rpc('invite_acceptances.create', { token })).status).toBe(200)
    expect((await ann.rpc('sessions.get')).body.data.user).toMatchObject({ email: 'ann@example.com', role: 'operator' })
  })
})
