import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, addUser, query, resetState, serverOptions, setupAdmin } from '../helpers'

describe('audit log', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('lets every signed-in role read it', async () => {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    for (const client of [admin, operator, viewer]) {
      const { status, body } = await client.rpc('events.list')
      expect(status).toBe(200)
      expect(body.data.length).toBeGreaterThan(0)
      expect(body.data[0].permissions).toEqual({ read: true })
    }
  })

  it('refuses anonymous readers and bad API keys', async () => {
    await setupAdmin()
    expect((await new Client().rpc('events.list')).status).toBe(401)
    expect((await new Client().rpcWithKey('cfy_nonsense', 'events.list')).status).toBe(401)
  })

  it('records the client address of who did it, for the audit log and the session list', async () => {
    await setupAdmin()
    const [event] = await query()`select ip from events where name = 'sessions.create' limit 1`
    expect(event?.ip).toBeTruthy()
    const [session] = await query()`select ip_address from sessions limit 1`
    expect(session?.ip_address).toBe(event?.ip)
  })

  it('records what happened, newest first, with the actor’s name', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'bob@example.com', role: 'viewer' })
    const { body } = await admin.rpc('events.list')
    expect(body.data.map((e: { name: string }) => e.name)).toEqual(['invites.create', 'sessions.create', 'users.create'])
    expect(body.data[0]).toMatchObject({ actor_type: 'user', actor_name: 'admin', subject_type: 'invite', data: { email: 'bob@example.com', role: 'viewer' } })
    expect(body.next_cursor).toBeNull()
  })

  it('filters by event name, actor, actor type, subject and time', async () => {
    const admin = await setupAdmin()
    const me = (await admin.rpc('sessions.get')).body.data.user
    await admin.rpc('invites.create', { email: 'bob@example.com' })
    await admin.rpc('invites.create', { email: 'carl@example.com' })
    const names = async (filter: object) => (await admin.rpc('events.list', filter)).body.data.map((e: { name: string }) => e.name)

    expect(await names({ name: 'invites.create' })).toEqual(['invites.create', 'invites.create'])
    expect(await names({ actor_id: me.id, name: 'sessions.create' })).toEqual(['sessions.create'])
    expect(await names({ actor_type: 'system' })).toEqual([])
    expect(await names({ actor_type: 'user' })).toHaveLength(4)
    const [invite] = (await admin.rpc('invites.list')).body.data
    expect(await names({ subject_type: 'invite', subject_id: invite.id })).toEqual(['invites.create'])
    expect(await names({ from: new Date(Date.now() + 60_000).toISOString() })).toEqual([])
    expect(await names({ to: new Date(Date.now() - 3_600_000).toISOString() })).toEqual([])
    expect((await admin.rpc('events.list', { from: 'yesterday' })).status).toBe(400)
  })

  it('pages with a keyset cursor without skipping or repeating entries', async () => {
    const admin = await setupAdmin()
    for (let i = 0; i < 6; i++) await admin.rpc('invites.create', { email: `user${i}@example.com` })
    const seen: string[] = []
    let cursor: string | undefined
    let pages = 0
    do {
      const { body } = await admin.rpc('events.list', { limit: 3, cursor })
      seen.push(...body.data.map((e: { id: string }) => e.id))
      cursor = body.next_cursor ?? undefined
      pages++
    } while (cursor)
    expect(pages).toBe(3)
    expect(seen).toHaveLength(8)
    expect(new Set(seen).size).toBe(8)
    expect((await admin.rpc('events.list', { cursor: 'garbage' })).body.error.code).toBe('invalid_cursor')
    // Well-formed cursors with values the database cannot compare are refused before the query.
    const encode = (keys: unknown[]) => Buffer.from(JSON.stringify(keys)).toString('base64url')
    for (const keys of [
      [new Date().toISOString(), 'not-a-uuid'],
      ['yesterday', '0b9a6d2e-3c61-4f0e-9a52-6f1f0f0d7a11'],
      ['2026-02-30T00:00:00+00:00', '0b9a6d2e-3c61-4f0e-9a52-6f1f0f0d7a11'],
    ]) {
      const bad = await admin.rpc('events.list', { cursor: encode(keys) })
      expect(bad.status).toBe(400)
      expect(bad.body.error.code).toBe('invalid_cursor')
    }
    expect((await admin.rpc('events.list', { limit: 1000 })).status).toBe(400)
  })

  it('has no way to change entries', async () => {
    const admin = await setupAdmin()
    const { body } = await admin.rpc('events.list')
    const id = body.data[0].id
    for (const action of ['update', 'delete', 'create']) {
      const response = await admin.rpc(`events.${action}`, { id })
      expect(response.status).toBe(404)
    }
    const [{ n }] = await query()`select count(*)::int as n from events`
    expect(n).toBe(body.data.length)
  })
})
