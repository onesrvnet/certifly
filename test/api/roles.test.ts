import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, addUser, query, resetState, serverOptions, setupAdmin, signInWithCode, waitForMail } from '../helpers'

async function me(client: Client) {
  return (await client.rpc('sessions.get')).body.data.user as { id: string; role: string; permissions: Record<string, boolean> }
}

describe('roles', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('lets an admin change another person’s role', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const target = await me(viewer)
    const { status, body } = await admin.rpc('users.update', { id: target.id, role: 'operator' })
    expect(status).toBe(200)
    expect(body.data.role).toBe('operator')
    expect((await me(viewer)).role).toBe('operator')
    expect(body.data.permissions).toMatchObject({ change_role: true, deactivate: true })
  })

  it('refuses role changes by non-admins, including on themselves', async () => {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const operatorMe = await me(operator)
    const viewerMe = await me(viewer)
    expect((await viewer.rpc('users.update', { id: viewerMe.id, role: 'admin' })).status).toBe(403)
    expect((await operator.rpc('users.update', { id: operatorMe.id, role: 'admin' })).status).toBe(403)
    // Another person's row is not readable for an operator, so it reads as not found.
    expect((await operator.rpc('users.update', { id: viewerMe.id, role: 'admin' })).status).toBe(404)
    expect((await me(viewer)).role).toBe('viewer')
    expect(viewerMe.permissions.change_role).toBe(false)
  })

  it('refuses to demote the last admin', async () => {
    const admin = await setupAdmin()
    const self = await me(admin)
    const { status, body } = await admin.rpc('users.update', { id: self.id, role: 'viewer' })
    expect(status).toBe(409)
    expect(body.error.code).toBe('last_admin')
    expect((await me(admin)).role).toBe('admin')
  })

  it('refuses to deactivate the last admin', async () => {
    const admin = await setupAdmin()
    await addUser(admin, 'viewer@example.com', 'viewer')
    const { status, body } = await admin.rpc('users.update', { id: (await me(admin)).id, deactivated: true })
    expect(status).toBe(409)
    expect(body.error.code).toBe('last_admin')
    expect((await admin.rpc('sessions.get')).status).toBe(200)
  })

  it('allows demoting an admin while another admin remains, and then protects the remaining one', async () => {
    const admin = await setupAdmin()
    const second = await addUser(admin, 'second@example.com', 'admin')
    const first = await me(admin)
    const secondMe = await me(second)
    expect((await admin.rpc('users.update', { id: first.id, role: 'operator' })).status).toBe(200)
    // The second admin is now the last one.
    const refused = await second.rpc('users.update', { id: secondMe.id, role: 'viewer' })
    expect(refused.status).toBe(409)
    expect(refused.body.error.code).toBe('last_admin')
  })

  it('deactivates a person: sessions end, sign-in stops, reactivating restores it', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const target = await me(viewer)
    expect((await admin.rpc('users.update', { id: target.id, deactivated: true })).status).toBe(200)

    expect((await viewer.rpc('sessions.get')).status).toBe(401)
    const blocked = await new Client().rpc('sign_in_codes.create', { email: 'viewer@example.com' })
    expect(blocked.status).toBe(200)
    expect((await admin.rpc('users.list')).body.data.map((u: { email: string }) => u.email)).not.toContain('viewer@example.com')
    expect((await admin.rpc('users.list', { include_deactivated: true })).body.data.map((u: { email: string }) => u.email)).toContain('viewer@example.com')

    expect((await admin.rpc('users.update', { id: target.id, deactivated: false })).status).toBe(200)
    const { result } = await signInWithCode('viewer@example.com')
    expect(result.status).toBe(200)
  })

  it('refuses non-admins deactivating anyone', async () => {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const adminMe = await me(admin)
    const { status } = await operator.rpc('users.update', { id: adminMe.id, deactivated: true })
    // The operator may not even read the admin's account.
    expect([403, 404]).toContain(status)
    expect((await admin.rpc('sessions.get')).status).toBe(200)
  })

  it('lets everyone read and rename only themselves; admins list everyone', async () => {
    const admin = await setupAdmin()
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const viewerMe = await me(viewer)
    const adminMe = await me(admin)

    expect((await viewer.rpc('users.list')).body.data).toHaveLength(1)
    expect((await admin.rpc('users.list')).body.data).toHaveLength(2)
    expect((await viewer.rpc('users.get', { id: adminMe.id })).status).toBe(404)
    expect((await viewer.rpc('users.update', { name: 'Vera' })).body.data.name).toBe('Vera')
    expect((await viewer.rpc('users.update', { id: adminMe.id, name: 'Hacked' })).status).toBe(404)
    expect((await admin.rpc('users.get', { id: viewerMe.id })).body.data.name).toBe('Vera')
  })

  it('lets operators look people up by name, with nothing but name, email and username', async () => {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const gone = await addUser(admin, 'gone@example.com', 'viewer')
    expect((await admin.rpc('users.update', { id: (await me(gone)).id, deactivated: true })).status).toBe(200)

    const listed = (await operator.rpc('users.list')).body.data as Record<string, unknown>[]
    expect(listed.map((u) => u.email).sort()).toEqual(['admin@example.com', 'op@example.com', 'viewer@example.com'])
    const other = listed.find((u) => u.email === 'viewer@example.com')!
    expect(Object.keys(other).sort()).toEqual(['email', 'id', 'name', 'username'])
    // Their own row stays complete, deactivated people and role filters stay with admins.
    expect(listed.find((u) => u.email === 'op@example.com')).toHaveProperty('role', 'operator')
    expect((await operator.rpc('users.list', { include_deactivated: true })).body.data.map((u: { email: string }) => u.email)).not.toContain('gone@example.com')
    expect((await operator.rpc('users.list', { query: 'viewer' })).body.data).toHaveLength(1)
    expect((await operator.rpc('users.get', { id: (await me(viewer)).id })).status).toBe(404)

    // Viewers still see only themselves, and admins the full rows.
    expect((await viewer.rpc('users.list')).body.data).toHaveLength(1)
    expect((await admin.rpc('users.list')).body.data.find((u: { email: string }) => u.email === 'viewer@example.com')).toHaveProperty('role', 'viewer')
  })

  it('keeps an admin when two admins demote each other at the same time', async () => {
    const admin = await setupAdmin()
    const second = await addUser(admin, 'second@example.com', 'admin')
    const firstId = (await me(admin)).id
    const secondId = (await me(second)).id
    const results = await Promise.all([
      admin.rpc('users.update', { id: secondId, role: 'viewer' }),
      second.rpc('users.update', { id: firstId, role: 'viewer' }),
    ])
    const [{ n }] = await query()`select count(*)::int as n from users where role = 'admin' and deleted_at is null`
    expect(n).toBeGreaterThanOrEqual(1)
    expect(results.map((r) => r.status).sort()).toEqual([200, 409])
  })

  it('keeps an admin when two admins demote themselves at the same time', async () => {
    const admin = await setupAdmin()
    const second = await addUser(admin, 'second@example.com', 'admin')
    const firstId = (await me(admin)).id
    const secondId = (await me(second)).id
    const results = await Promise.all([
      admin.rpc('users.update', { id: firstId, deactivated: true }),
      second.rpc('users.update', { id: secondId, role: 'operator' }),
    ])
    const [{ n }] = await query()`select count(*)::int as n from users where role = 'admin' and deleted_at is null`
    expect(n).toBe(1)
    expect(results.map((r) => r.status).sort()).toEqual([200, 409])
  })

  it('deletes the API keys and pending invites of someone deactivated, so reactivating does not bring them back', async () => {
    const admin = await setupAdmin()
    const second = await addUser(admin, 'second@example.com', 'admin')
    const secondId = (await me(second)).id
    const { secret } = (await second.rpc('api_keys.create', { name: 'ci' })).body.data
    expect((await second.rpc('invites.create', { email: 'friend@example.com' })).status).toBe(200)
    await waitForMail('friend@example.com')
    expect((await admin.rpc('invites.create', { email: 'other@example.com' })).status).toBe(200)
    await waitForMail('other@example.com')

    expect((await admin.rpc('users.update', { id: secondId, deactivated: true })).status).toBe(200)
    expect(await query()`select id from api_keys where user_id = ${secondId}`).toHaveLength(0)
    const pending = (await admin.rpc('invites.list', { status: 'pending' })).body.data.map((i: { email: string }) => i.email)
    expect(pending).toEqual(['other@example.com'])

    expect((await admin.rpc('users.update', { id: secondId, deactivated: false })).status).toBe(200)
    expect((await new Client().rpcWithKey(secret, 'sessions.get')).status).toBe(401)
    const [event] = (await admin.rpc('events.list', { name: 'users.deactivate' })).body.data
    expect(event.data).toEqual({ api_keys_deleted: 1, invites_deleted: 1, ssh_certificates_revoked: 0 })
  })
})
