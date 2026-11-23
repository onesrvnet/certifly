import { describe, expect, it, vi } from 'vitest'
import type { Context } from '../src/context'
import type { Actor } from '../src/policies'
import { setSetting } from '../src/settings'

/** A database that records which statements ran, and an audit log that records events. */
function context() {
  const ran: string[] = []
  const events: unknown[] = []
  const db = {
    delete: () => ({ where: async () => ran.push('delete') }),
    insert: () => ({
      values: (values: Record<string, unknown>) => {
        if ('actor_type' in values) {
          events.push(values)
          return { returning: async () => [{ id: 'e1', ...values }] }
        }
        return { onConflictDoUpdate: async () => ran.push('upsert') }
      },
    }),
  }
  return { ctx: { db, emit: vi.fn() } as unknown as Context, ran, events }
}

const admin: Actor = { id: 'u1', role: 'admin', kind: 'session', reauth_at: new Date() }

describe('setSetting', () => {
  it('stores a value', async () => {
    const { ctx, ran } = context()
    await setSetting(ctx, admin, 'instance.name', 'Acme')
    expect(ran).toEqual(['upsert'])
  })

  it('removes the setting for null, so it reads as never set', async () => {
    const { ctx, ran, events } = context()
    await setSetting(ctx, admin, 'instance.name', null)
    expect(ran).toEqual(['delete'])
    expect(events[0]).toMatchObject({ name: 'settings.update', data: { key: 'instance.name', removed: true } })
  })

  it('refuses a missing value and a stale session', async () => {
    const { ctx } = context()
    await expect(setSetting(ctx, admin, 'instance.name', undefined)).rejects.toMatchObject({ code: 'validation_error' })
    await expect(setSetting(ctx, { ...admin, reauth_at: null }, 'instance.name', 'x')).rejects.toMatchObject({ code: 'reauth_required' })
  })
})
