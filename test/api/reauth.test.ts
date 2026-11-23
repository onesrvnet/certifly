import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, latestSigninMail, query, resetState, serverOptions, setupAdmin, sentMails } from '../helpers'

describe('re-authentication', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  const session = async (client: Client) => (await client.rpc('sessions.get')).body.data.session

  /** Pretend the last confirmation was `minutes` ago. */
  const age = (minutes: number) => query()`update sessions set reauth_at = now() - make_interval(mins => ${minutes})`

  it('counts a fresh sign-in as confirmed', async () => {
    const admin = await setupAdmin()
    expect(await session(admin)).toMatchObject({ reauth_fresh: true, reauth_max_age_seconds: 600 })
  })

  it('reports a session as stale after ten minutes', async () => {
    const admin = await setupAdmin()
    await age(9)
    expect((await session(admin)).reauth_fresh).toBe(true)
    await age(11)
    expect((await session(admin)).reauth_fresh).toBe(false)
  })

  it('confirms again with the emailed code', async () => {
    const admin = await setupAdmin()
    await age(30)
    const started = await admin.rpc('reauthentications.create', { method: 'email' })
    expect(started.status).toBe(200)
    // The code goes to the signed-in person's own address.
    const mails = await sentMails('admin@example.com')
    expect(mails).toHaveLength(2)
    const { code } = await latestSigninMail('admin@example.com')

    const verified = await admin.rpc('reauthentications.verify', { method: 'email', code })
    expect(verified.status).toBe(200)
    expect(await session(admin)).toMatchObject({ reauth_fresh: true })
    const events = (await admin.rpc('events.list', { name: 'sessions.reauthenticate' })).body.data
    expect(events).toHaveLength(1)
    expect(events[0].data).toEqual({ method: 'email' })
  })

  it('refuses a wrong code and stays unconfirmed', async () => {
    const admin = await setupAdmin()
    await age(30)
    await admin.rpc('reauthentications.create', { method: 'email' })
    const { code } = await latestSigninMail('admin@example.com')
    const wrong = code === '000000' ? '111111' : '000000'
    const refused = await admin.rpc('reauthentications.verify', { method: 'email', code: wrong })
    expect(refused.status).toBe(401)
    expect(refused.body.error.code).toBe('invalid_code')
    expect((await session(admin)).reauth_fresh).toBe(false)
  })

  it('refuses a malformed code before looking at it', async () => {
    const admin = await setupAdmin()
    expect((await admin.rpc('reauthentications.verify', { method: 'email', code: 'abc' })).status).toBe(400)
  })

  it('refuses re-authenticating without a session', async () => {
    expect((await new Client().rpc('reauthentications.create', { method: 'email' })).status).toBe(401)
    expect((await new Client().rpc('reauthentications.verify', { method: 'email', code: '123456' })).status).toBe(401)
  })

  it('refuses API keys, which can never qualify', async () => {
    const admin = await setupAdmin()
    const { secret } = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data
    expect((await new Client().rpcWithKey(secret, 'reauthentications.create', { method: 'email' })).status).toBe(403)
    expect((await new Client().rpcWithKey(secret, 'reauthentications.verify', { method: 'email', code: '123456' })).status).toBe(403)
    expect((await new Client().rpcWithKey(secret, 'sessions.get')).body.data.session).toBeNull()
  })

  it('offers no identity provider re-authentication when no provider is configured', async () => {
    const admin = await setupAdmin()
    expect((await admin.get('/auth/oidc/reauth?return_to=/settings/security')).status).toBe(404)
  })
})
