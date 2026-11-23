import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, confirmWithCode, latestSigninMail, query, resetState, serverOptions, setupAdmin, userId, waitForMail } from '../helpers'
import { SoftwareAuthenticator } from '../support/authenticator'

describe('step-up for credentials and admin changes', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  const origin = () => process.env.URL!
  const authenticator = () => new SoftwareAuthenticator(new URL(origin()).hostname, origin())

  /**
   * An admin with a passkey, an API key and a pending invite, a viewer and a deactivated
   * person: everything each sensitive action below needs.
   */
  async function world() {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const gone = await addUser(admin, 'gone@example.com', 'viewer')
    const goneId = await userId(gone)
    expect((await admin.rpc('users.update', { id: goneId, deactivated: true })).status).toBe(200)
    const device = authenticator()
    const options = (await admin.rpc('passkey_registrations.create')).body.data
    expect((await admin.rpc('passkey_registrations.verify', { response: device.register(options) })).status).toBe(200)
    const passkey = (await admin.rpc('passkeys.list')).body.data[0]
    const key = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data
    const invite = (await admin.rpc('invites.create', { email: 'pending@example.com' })).body.data
    await waitForMail('pending@example.com')
    return { admin, viewerId: await userId(viewer), goneId, passkey, key, invite }
  }

  type World = Awaited<ReturnType<typeof world>>
  /** Every step-up action, as a call a client can make. */
  const actions: [string, (w: World) => [string, object]][] = [
    ['start adding a passkey', () => ['passkey_registrations.create', {}]],
    ['remove a passkey', (w) => ['passkeys.delete', { id: w.passkey.id }]],
    ['create an API key', () => ['api_keys.create', { name: 'more' }]],
    ['invite an admin', () => ['invites.create', { email: 'new-admin@example.com', role: 'admin' }]],
    ['invite a viewer', () => ['invites.create', { email: 'new-viewer@example.com', role: 'viewer' }]],
    ['revoke an invite', (w) => ['invites.delete', { id: w.invite.id }]],
    ['change a role', (w) => ['users.update', { id: w.viewerId, role: 'operator' }]],
    ['deactivate someone', (w) => ['users.update', { id: w.viewerId, deactivated: true }]],
    ['reactivate someone', (w) => ['users.update', { id: w.goneId, deactivated: false }]],
    ['update a setting', () => ['settings.update', { key: 'instance.name', value: 'Acme' }]],
  ]

  it('asks a session that has not confirmed it is the person lately to do so first, and changes nothing', async () => {
    const w = await world()
    await ageSessions(11)
    for (const [label, action] of actions) {
      const [method, body] = action(w)
      const { status, body: answer } = await w.admin.rpc(method, body)
      expect({ label, status, code: answer.error?.code }).toEqual({ label, status: 403, code: 'reauth_required' })
    }
    expect((await w.admin.rpc('passkeys.list')).body.data).toHaveLength(1)
    expect((await w.admin.rpc('api_keys.list')).body.data).toHaveLength(1)
    expect((await w.admin.rpc('invites.list', { status: 'pending' })).body.data).toHaveLength(1)
    expect((await w.admin.rpc('users.get', { id: w.viewerId })).body.data).toMatchObject({ role: 'viewer', deleted_at: null })
    expect((await w.admin.rpc('users.get', { id: w.goneId })).body.data.deleted_at).not.toBeNull()
    expect((await w.admin.rpc('settings.list')).body.data).toEqual({})
  })

  it('never lets an API key do them, even right after its owner confirmed', async () => {
    const w = await world()
    for (const [label, action] of actions) {
      const [method, body] = action(w)
      const { status } = await new Client().rpcWithKey(w.key.secret, method, body)
      expect({ label, status }).toEqual({ label, status: 403 })
    }
    expect((await w.admin.rpc('api_keys.list')).body.data).toHaveLength(1)
    expect((await w.admin.rpc('users.get', { id: w.viewerId })).body.data.role).toBe('viewer')
    // Reading stays open to keys.
    expect((await new Client().rpcWithKey(w.key.secret, 'users.list')).status).toBe(200)
    expect((await new Client().rpcWithKey(w.key.secret, 'users.get', { id: w.viewerId })).status).toBe(200)
    expect((await new Client().rpcWithKey(w.key.secret, 'events.list')).status).toBe(200)
  })

  it('allows them once the session confirmed again', async () => {
    const w = await world()
    await ageSessions(30)
    await confirmWithCode(w.admin, 'admin@example.com')
    for (const [label, action] of actions) {
      const [method, body] = action(w)
      const { status } = await w.admin.rpc(method, body)
      expect({ label, status }).toEqual({ label, status: 200 })
    }
    expect((await w.admin.rpc('settings.list')).body.data).toEqual({ 'instance.name': 'Acme' })
    // The invite mails go out in the background; let them land before the next test clears the outbox.
    await waitForMail('new-viewer@example.com')
  })

  it('registers a passkey only after confirming again, also when the browser step is already under way', async () => {
    const admin = await setupAdmin()
    const device = authenticator()
    const options = (await admin.rpc('passkey_registrations.create')).body.data
    await ageSessions(11)

    const late = await admin.rpc('passkey_registrations.verify', { response: device.register(options) })
    expect(late.status).toBe(403)
    expect(late.body.error.code).toBe('reauth_required')
    expect((await admin.rpc('passkey_registrations.create')).body.error.code).toBe('reauth_required')
    expect((await admin.rpc('passkeys.list')).body.data).toHaveLength(0)

    await confirmWithCode(admin, 'admin@example.com')
    const fresh = (await admin.rpc('passkey_registrations.create')).body.data
    expect((await admin.rpc('passkey_registrations.verify', { response: device.register(fresh) })).status).toBe(200)
    expect((await admin.rpc('passkeys.list')).body.data).toHaveLength(1)
  })

  it('tells someone who may not do an action that, rather than asking them to confirm', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    await ageSessions(30)
    const refused = await viewer.rpc('invites.create', { email: 'x@example.com' })
    expect(refused.status).toBe(403)
    expect(refused.body.error.code).toBe('forbidden')
  })

  it('counts a confirmation for the session it happened in only', async () => {
    const admin = await setupAdmin()
    const other = new Client()
    await other.rpc('sign_in_codes.create', { email: 'admin@example.com' })
    const { token } = await latestSigninMail('admin@example.com')
    await other.rpc('sign_in_codes.verify', { token })
    await ageSessions(30)
    await confirmWithCode(admin, 'admin@example.com')
    expect((await admin.rpc('api_keys.create', { name: 'here' })).status).toBe(200)
    expect((await other.rpc('api_keys.create', { name: 'there' })).body.error.code).toBe('reauth_required')
    const [{ n }] = await query()`select count(*)::int as n from sessions where reauth_at > now() - interval '1 minute'`
    expect(n).toBe(1)
  })
})
