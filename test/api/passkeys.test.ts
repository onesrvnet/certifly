import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, addUser, query, resetState, serverOptions, setupAdmin } from '../helpers'
import { SoftwareAuthenticator } from '../support/authenticator'

describe('passkeys', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  const origin = () => process.env.URL!
  const authenticator = () => new SoftwareAuthenticator(new URL(origin()).hostname, origin())

  async function register(client: Client, device = authenticator()) {
    const options = (await client.rpc('passkey_registrations.create')).body.data
    const verified = await client.rpc('passkey_registrations.verify', { response: device.register(options), name: 'Laptop' })
    expect(verified.status).toBe(200)
    return device
  }

  it('registers a passkey and signs in with it', async () => {
    const admin = await setupAdmin()
    const device = await register(admin)
    expect((await admin.rpc('passkeys.list')).body.data).toMatchObject([{ name: 'Laptop' }])

    const browser = new Client()
    const options = (await browser.rpc('passkey_sign_ins.create')).body.data
    const result = await browser.rpc('passkey_sign_ins.verify', { response: device.authenticate(options) })
    expect(result.status).toBe(200)
    expect((await browser.rpc('sessions.get')).body.data.user.email).toBe('admin@example.com')
  })

  it('refuses a passkey response that does not match the challenge', async () => {
    const admin = await setupAdmin()
    const device = await register(admin)
    const browser = new Client()
    await browser.rpc('passkey_sign_ins.create')
    const other = (await new Client().rpc('passkey_sign_ins.create')).body.data
    const refused = await browser.rpc('passkey_sign_ins.verify', { response: device.authenticate(other) })
    expect(refused.status).toBe(401)
    expect((await browser.rpc('sessions.get')).status).toBe(401)
  })

  it('refuses a passkey sign-in without a pending challenge, and an unknown passkey', async () => {
    const admin = await setupAdmin()
    const device = await register(admin)
    const noChallenge = await new Client().rpc('passkey_sign_ins.verify', { response: device.authenticate({ challenge: 'x' }) })
    expect(noChallenge.body.error.code).toBe('passkey_expired')

    const browser = new Client()
    const options = (await browser.rpc('passkey_sign_ins.create')).body.data
    const unknown = authenticator()
    const refused = await browser.rpc('passkey_sign_ins.verify', { response: unknown.authenticate(options) })
    expect(refused.status).toBe(401)
  })

  it('confirms again with a passkey, but not with somebody else’s', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const adminDevice = await register(admin)
    const viewerDevice = await register(viewer)

    await query()`update sessions set reauth_at = now() - interval '1 hour'`
    const options = (await admin.rpc('reauthentications.create', { method: 'passkey' })).body.data.options
    const foreign = await admin.rpc('reauthentications.verify', { method: 'passkey', response: viewerDevice.authenticate(options) })
    expect(foreign.status).toBe(401)
    expect((await admin.rpc('sessions.get')).body.data.session.reauth_fresh).toBe(false)

    const again = (await admin.rpc('reauthentications.create', { method: 'passkey' })).body.data.options
    const ok = await admin.rpc('reauthentications.verify', { method: 'passkey', response: adminDevice.authenticate(again) })
    expect(ok.status).toBe(200)
    expect((await admin.rpc('sessions.get')).body.data.session.reauth_fresh).toBe(true)
  })

  it('renames and deletes only one’s own passkeys', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    await register(admin)
    const [passkey] = (await admin.rpc('passkeys.list')).body.data
    expect((await viewer.rpc('passkeys.update', { id: passkey.id, name: 'Mine now' })).status).toBe(404)
    expect((await viewer.rpc('passkeys.delete', { id: passkey.id })).status).toBe(404)
    expect((await admin.rpc('passkeys.update', { id: passkey.id, name: 'Work laptop' })).body.data.name).toBe('Work laptop')
    expect((await admin.rpc('passkeys.delete', { id: passkey.id })).status).toBe(200)
    expect((await admin.rpc('passkeys.list')).body.data).toHaveLength(0)
  })

  it('refuses a passkey that is already registered, with a stable code and no library details', async () => {
    const admin = await setupAdmin()
    const device = await register(admin)
    const options = (await admin.rpc('passkey_registrations.create')).body.data
    const again = await admin.rpc('passkey_registrations.verify', { response: device.register(options) })
    expect(again.status).toBe(409)
    expect(again.body.error.code).toBe('passkey_exists')

    const broken = (await admin.rpc('passkey_registrations.create')).body.data
    const refused = await admin.rpc('passkey_registrations.verify', { response: { ...authenticator().register(broken), type: 'nonsense' } })
    expect(refused.status).toBe(400)
    expect(refused.body.error).toEqual({ code: 'passkey_invalid', message: 'The passkey could not be verified' })
  })
})
