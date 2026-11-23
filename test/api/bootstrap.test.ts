import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, latestSigninMail, query, resetState, sentMails, serverOptions, setupAdmin, signInWithCode } from '../helpers'

describe('bootstrap', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('reports setup needed on an empty instance, without a setup token', async () => {
    const { status, body } = await new Client().rpc('auth_config.get')
    expect(status).toBe(200)
    expect(body.data).toMatchObject({ needs_setup: true, setup_token_required: false, oidc: { enabled: false } })
  })

  it('makes the first person to sign in an admin', async () => {
    const client = await setupAdmin('owner@example.com')
    const { status, body } = await client.rpc('sessions.get')
    expect(status).toBe(200)
    expect(body.data.user).toMatchObject({ email: 'owner@example.com', role: 'admin', name: 'owner' })
    expect(body.data.instance.permissions).toMatchObject({ manage_users: true, read_settings: true, update_settings: true, read_events: true })
    expect(body.data.session).toMatchObject({ current: true, reauth_fresh: true })
    expect((await new Client().rpc('auth_config.get')).body.data.needs_setup).toBe(false)
  })

  it('signs in with the emailed code as well as the link', async () => {
    await setupAdmin()
    const { client, result } = await signInWithCode('admin@example.com')
    expect(result.status).toBe(200)
    expect((await client.rpc('sessions.get')).body.data.user.role).toBe('admin')
  })

  it('normalizes the email address and rejects malformed ones', async () => {
    const client = new Client()
    expect((await client.rpc('sign_in_codes.create', { email: 'nope' })).status).toBe(400)
    await client.rpc('sign_in_codes.create', { email: ' Owner@Example.COM ' })
    expect(await sentMails('owner@example.com')).toHaveLength(1)
  })

  it('refuses a person nobody invited once the instance has users, without revealing that', async () => {
    await setupAdmin()
    const stranger = new Client()
    const created = await stranger.rpc('sign_in_codes.create', { email: 'stranger@example.com' })
    // Same answer as for a known address, but no mail is sent.
    expect(created.status).toBe(200)
    expect(created.body.data).toEqual({ sent: true })
    expect(await sentMails('stranger@example.com')).toHaveLength(0)
    const verified = await stranger.rpc('sign_in_codes.verify', { email: 'stranger@example.com', code: '123456' })
    expect(verified.status).toBe(401)
    expect(verified.body.error.code).toBe('invalid_code')
    const [{ n }] = await query()`select count(*)::int as n from users`
    expect(n).toBe(1)
  })

  it('does not reopen setup after the only user is deactivated', async () => {
    const admin = await setupAdmin()
    const me = (await admin.rpc('sessions.get')).body.data.user
    await query()`update users set deleted_at = now() where id = ${me.id}`
    expect((await new Client().rpc('auth_config.get')).body.data.needs_setup).toBe(false)
    await new Client().rpc('sign_in_codes.create', { email: 'someone@example.com' })
    expect(await sentMails('someone@example.com')).toHaveLength(0)
  })

  it('keeps email addresses unique whatever their case, also in the database itself', async () => {
    await setupAdmin()
    await expect(query()`insert into users (email, name) values ('ADMIN@Example.com', 'copy')`).rejects.toMatchObject({ code: '23505' })
  })

  it('reports that email sign-in is available when mail can be sent', async () => {
    expect((await new Client().rpc('auth_config.get')).body.data.email_enabled).toBe(true)
  })

  it('answers unauthenticated requests with 401 and a stable code', async () => {
    const { status, body } = await new Client().rpc('sessions.get')
    expect(status).toBe(401)
    expect(body.error.code).toBe('authentication_required')
  })

  it('refuses a used link', async () => {
    const client = new Client()
    await client.rpc('sign_in_codes.create', { email: 'admin@example.com' })
    const { token } = await latestSigninMail('admin@example.com')
    expect((await client.rpc('sign_in_codes.verify', { token })).status).toBe(200)
    const again = await new Client().rpc('sign_in_codes.verify', { token })
    expect(again.status).toBe(401)
    expect(again.body.error.code).toBe('invalid_token')
  })
})
