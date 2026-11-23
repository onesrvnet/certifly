import { describe, expect, it, vi } from 'vitest'
import { eventFor, recordEvent, systemEvent, withTransaction, type EventRow } from '../src/audit'
import type { Context } from '../src/context'
import { AuthorizationError } from '../src/errors'
import { listEvents } from '../src/audit'
import type { Actor } from '../src/policies'

const user: Actor = { id: 'u1', role: 'operator', kind: 'session', ip: '203.0.113.7', reauth_at: null }

describe('eventFor', () => {
  it('describes what a signed-in user did', () => {
    expect(eventFor(user, 'users.update_role', { type: 'user', id: 'u2' }, { to: 'viewer' })).toEqual({
      actor_type: 'user',
      actor_id: 'u1',
      name: 'users.update_role',
      subject_type: 'user',
      subject_id: 'u2',
      data: { to: 'viewer' },
      ip: '203.0.113.7',
    })
  })

  it('names the key, and keeps its owner, when an API key acted', () => {
    const event = eventFor({ ...user, kind: 'api_key', api_key_id: 'k1' }, 'api_keys.create')
    expect(event).toMatchObject({ actor_type: 'api_key', actor_id: 'k1', data: { user_id: 'u1' }, subject_type: null, subject_id: null })
  })

  it('falls back to the owner when the key id is unknown', () => {
    expect(eventFor({ ...user, kind: 'api_key' }, 'x')).toMatchObject({ actor_type: 'api_key', actor_id: 'u1' })
  })
})

describe('systemEvent', () => {
  it('has no actor id', () => {
    expect(systemEvent('cleanup.expired')).toMatchObject({ actor_type: 'system', name: 'cleanup.expired', data: {} })
    expect(systemEvent('cleanup.expired').actor_id).toBeUndefined()
  })
})

describe('recordEvent', () => {
  function context(emit: (row: EventRow) => void) {
    const stored: unknown[] = []
    const db = {
      insert: () => ({
        values: (row: Record<string, unknown>) => {
          stored.push(row)
          return { returning: async () => [{ id: 'e1', ...row }] }
        },
      }),
    }
    return { ctx: { db, emit } as unknown as Context, stored }
  }

  it('stores the event with empty defaults and tells subscribers', async () => {
    const emit = vi.fn()
    const { ctx, stored } = context(emit)
    const row = await recordEvent(ctx, { actor_type: 'system', name: 'cleanup.expired' })
    expect(stored[0]).toEqual({
      actor_type: 'system',
      actor_id: null,
      name: 'cleanup.expired',
      subject_type: null,
      subject_id: null,
      data: {},
      ip: null,
    })
    expect(emit).toHaveBeenCalledWith(row)
  })

  it('keeps the event when a subscriber fails', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const { ctx } = context(() => {
      throw new Error('subscriber down')
    })
    await expect(recordEvent(ctx, { actor_type: 'system', name: 'x' })).resolves.toMatchObject({ id: 'e1' })
  })
})

describe('withTransaction', () => {
  /** A database whose transactions run the callback with a transaction object of their own. */
  function context(emit: (row: EventRow) => void) {
    const insert = () => ({
      values: (row: Record<string, unknown>) => ({ returning: async () => [{ id: 'e1', ...row }] }),
    })
    const tx = { insert }
    const db = { insert, transaction: async (fn: (t: typeof tx) => Promise<unknown>) => fn(tx) }
    return { ctx: { db, emit } as unknown as Context, tx }
  }

  it('tells subscribers about events only after the transaction committed', async () => {
    const emit = vi.fn()
    const { ctx } = context(emit)
    await withTransaction(ctx, async (tx) => {
      await recordEvent(ctx, { actor_type: 'system', name: 'x' }, tx)
      expect(emit).not.toHaveBeenCalled()
    })
    expect(emit).toHaveBeenCalledOnce()
  })

  it('tells nobody when the transaction rolled back', async () => {
    const emit = vi.fn()
    const { ctx } = context(emit)
    await expect(
      withTransaction(ctx, async (tx) => {
        await recordEvent(ctx, { actor_type: 'system', name: 'x' }, tx)
        throw new Error('rolled back')
      }),
    ).rejects.toThrow('rolled back')
    expect(emit).not.toHaveBeenCalled()
  })

  it('refuses a transaction it did not open, whose commit it could not wait for', async () => {
    const { ctx, tx } = context(vi.fn())
    await expect(recordEvent(ctx, { actor_type: 'system', name: 'x' }, tx as never)).rejects.toThrow('withTransaction')
  })
})

describe('listEvents', () => {
  it('is open to every role and refuses nobody who is signed in', async () => {
    // The check comes before any query, so a context without a database proves it.
    for (const role of ['admin', 'operator', 'viewer'] as const) {
      await expect(listEvents({} as Context, { ...user, role }, { limit: 10 })).rejects.not.toBeInstanceOf(AuthorizationError)
    }
  })
})
