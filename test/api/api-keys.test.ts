import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, addUser, query, resetState, serverOptions, setupAdmin } from '../helpers'

describe('api keys', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  async function createKey(client: Client, name = 'ci') {
    const { status, body } = await client.rpc('api_keys.create', { name })
    expect(status).toBe(200)
    return body.data as { id: string; secret: string; last4: string }
  }

  it('creates a key whose secret is shown once and never stored', async () => {
    const admin = await setupAdmin()
    const key = await createKey(admin)
    expect(key.secret).toMatch(/^cfy_/)
    expect(key.secret.endsWith(key.last4)).toBe(true)
    const listed = (await admin.rpc('api_keys.list')).body
    expect(JSON.stringify(listed)).not.toContain(key.secret)
    expect(listed.data).toHaveLength(1)
    const [row] = await query()`select secret_hash from api_keys`
    expect(row!.secret_hash).not.toBe(key.secret)
  })

  it('lets a key act with its owner’s role', async () => {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const key = await createKey(operator)
    const me = await new Client().rpcWithKey(key.secret, 'sessions.get')
    expect(me.status).toBe(200)
    expect(me.body.data.user).toMatchObject({ email: 'op@example.com', role: 'operator' })
    expect(me.body.data.session).toBeNull()
    // An operator key still cannot do admin work.
    expect((await new Client().rpcWithKey(key.secret, 'invites.list')).status).toBe(403)
    expect((await new Client().rpcWithKey(key.secret, 'events.list')).status).toBe(200)
  })

  it('refuses creating keys with a key, and other session-only actions', async () => {
    const admin = await setupAdmin()
    const key = await createKey(admin)
    const viaKey = await new Client().rpcWithKey(key.secret, 'api_keys.create', { name: 'spread' })
    expect(viaKey.status).toBe(403)
    expect((await admin.rpc('api_keys.list')).body.data).toHaveLength(1)
    expect((await new Client().rpcWithKey(key.secret, 'passkey_registrations.create')).status).toBe(403)
    expect((await new Client().rpcWithKey(key.secret, 'sessions.list')).status).toBe(403)
  })

  it('refuses unknown, deleted and expired keys', async () => {
    const admin = await setupAdmin()
    expect((await new Client().rpcWithKey('cfy_nonsense', 'sessions.get')).status).toBe(401)
    expect((await new Client().rpcWithKey('not-a-key', 'sessions.get')).status).toBe(401)

    const key = await createKey(admin)
    expect((await new Client().rpcWithKey(key.secret, 'sessions.get')).status).toBe(200)
    expect((await admin.rpc('api_keys.delete', { id: key.id })).status).toBe(200)
    expect((await new Client().rpcWithKey(key.secret, 'sessions.get')).status).toBe(401)

    const expiring = await createKey(admin, 'short')
    await query()`update api_keys set expires_at = now() - interval '1 minute' where id = ${expiring.id}`
    expect((await new Client().rpcWithKey(expiring.secret, 'sessions.get')).status).toBe(401)
  })

  it('refuses keys that expire in the past', async () => {
    const admin = await setupAdmin()
    const { status } = await admin.rpc('api_keys.create', { name: 'old', expires_at: new Date(Date.now() - 60_000).toISOString() })
    expect(status).toBe(400)
  })

  it('keeps keys private to their owner', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const adminKey = await createKey(admin)
    expect((await viewer.rpc('api_keys.list')).body.data).toHaveLength(0)
    expect((await viewer.rpc('api_keys.delete', { id: adminKey.id })).status).toBe(404)
    expect((await admin.rpc('api_keys.list')).body.data).toHaveLength(1)
  })

  it('stops a key when its owner is deactivated', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const key = await createKey(viewer)
    const me = (await viewer.rpc('sessions.get')).body.data.user
    await admin.rpc('users.update', { id: me.id, deactivated: true })
    expect((await new Client().rpcWithKey(key.secret, 'sessions.get')).status).toBe(401)
  })

  it('records key use in the audit log as the key, never with its secret', async () => {
    const admin = await setupAdmin()
    const key = await createKey(admin)
    const viaKey = new Client()
    await viaKey.rpc('events.list', {}, { authorization: `Bearer ${key.secret}` })
    const events = (await admin.rpc('events.list', { name: 'api_keys.create' })).body
    expect(events.data).toHaveLength(1)
    expect(JSON.stringify(events)).not.toContain(key.secret)
  })
})
