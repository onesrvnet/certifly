import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, addUser, query, resetState, serverOptions, setupAdmin, signInWithCode } from '../helpers'

describe('sessions', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('signs out the current session', async () => {
    const admin = await setupAdmin()
    expect((await admin.rpc('sessions.delete')).status).toBe(200)
    expect((await admin.rpc('sessions.get')).status).toBe(401)
  })

  it('lists own sessions and ends another one, but not somebody else’s', async () => {
    const first = await setupAdmin()
    const { client: second } = await signInWithCode('admin@example.com')
    const list = (await first.rpc('sessions.list')).body.data
    expect(list).toHaveLength(2)
    expect(list.filter((s: { current: boolean }) => s.current)).toHaveLength(1)
    const other = list.find((s: { current: boolean }) => !s.current)

    const viewer = await addUser(first, 'viewer@example.com', 'viewer')
    expect((await viewer.rpc('sessions.delete', { id: other.id })).status).toBe(404)
    expect((await second.rpc('sessions.get')).status).toBe(200)

    expect((await first.rpc('sessions.delete', { id: other.id })).status).toBe(200)
    expect((await first.rpc('sessions.get')).status).toBe(200)
    expect((await second.rpc('sessions.get')).status).toBe(401)
    expect((await first.rpc('sessions.delete', { id: other.id })).status).toBe(404)
  })

  it('ends a session left unused for 14 days', async () => {
    const first = await setupAdmin()
    const { client: second } = await signInWithCode('admin@example.com')
    await query()`update sessions set last_active_at = now() - interval '15 days' where id = (select id from sessions order by created_at desc limit 1)`
    expect((await second.rpc('sessions.get')).status).toBe(401)
    expect((await first.rpc('sessions.list')).body.data).toHaveLength(1)
    // Activity keeps it going: 13 days unused is fine.
    await query()`update sessions set last_active_at = now() - interval '13 days'`
    expect((await first.rpc('sessions.get')).status).toBe(200)
  })

  it('does not list sessions for anonymous callers', async () => {
    expect((await new Client().rpc('sessions.list')).status).toBe(401)
  })
})
