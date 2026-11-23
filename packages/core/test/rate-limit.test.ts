import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Context } from '../src/context'
import { evaluate, hit, MAX_WINDOW_SEC, windowOf } from '../src/rate-limit'

afterEach(() => vi.restoreAllMocks())

const at = (iso: string) => new Date(iso).getTime()

describe('windowOf', () => {
  it('aligns windows to multiples of their length', () => {
    const { start, reset } = windowOf(at('2026-11-22T12:34:56Z'), 60)
    expect(start.toISOString()).toBe('2026-11-22T12:34:00.000Z')
    expect(reset).toBe(4)
  })

  it('puts a request on a boundary into the new window', () => {
    const { start, reset } = windowOf(at('2026-11-22T12:35:00Z'), 60)
    expect(start.toISOString()).toBe('2026-11-22T12:35:00.000Z')
    expect(reset).toBe(60)
  })

  it('handles hour-long windows', () => {
    const { start, reset } = windowOf(at('2026-11-22T12:34:56.789Z'), 3600)
    expect(start.toISOString()).toBe('2026-11-22T12:00:00.000Z')
    expect(reset).toBe(1504)
  })

  it('gives every request in a window the same start', () => {
    const starts = new Set([0, 1, 30, 59].map((s) => windowOf(at('2026-11-22T12:34:00Z') + s * 1000, 60).start.getTime()))
    expect(starts.size).toBe(1)
  })
})

describe('evaluate', () => {
  it('allows requests up to the limit and refuses the next one', () => {
    expect(evaluate(1, 3, 10)).toEqual({ allowed: true, remaining: 2, reset: 10 })
    expect(evaluate(3, 3, 10)).toEqual({ allowed: true, remaining: 0, reset: 10 })
    expect(evaluate(4, 3, 10)).toEqual({ allowed: false, remaining: 0, reset: 10 })
    expect(evaluate(100, 3, 10).remaining).toBe(0)
  })
})

/** A database whose upsert reports the count after each call, like the real counter. */
function counterContext(options: { fail?: boolean } = {}) {
  const counts = new Map<string, number>()
  const values: { key: string; window_start: Date }[] = []
  const db = {
    insert: () => ({
      values: (row: { key: string; window_start: Date }) => {
        values.push(row)
        return {
          onConflictDoUpdate: () => ({
            returning: async () => {
              if (options.fail) throw new Error('connection refused')
              const id = `${row.key}@${row.window_start.toISOString()}`
              const count = (counts.get(id) ?? 0) + 1
              counts.set(id, count)
              return [{ count }]
            },
          }),
        }
      },
    }),
  }
  return { ctx: { db } as unknown as Context, values }
}

describe('hit', () => {
  const now = new Date('2026-11-22T12:34:56Z')

  it('counts requests in a window and refuses those over the limit', async () => {
    const { ctx } = counterContext()
    const results = []
    for (let i = 0; i < 4; i++) results.push(await hit(ctx, 'signin:ip', 3, 60, now))
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false])
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0])
    expect(results[0]!.reset).toBe(4)
  })

  it('starts counting again in the next window', async () => {
    const { ctx } = counterContext()
    for (let i = 0; i < 4; i++) await hit(ctx, 'k', 3, 60, now)
    const next = await hit(ctx, 'k', 3, 60, new Date(now.getTime() + 5000))
    expect(next).toEqual({ allowed: true, remaining: 2, reset: 59 })
  })

  it('counts keys separately', async () => {
    const { ctx } = counterContext()
    await hit(ctx, 'a', 1, 60, now)
    expect((await hit(ctx, 'b', 1, 60, now)).allowed).toBe(true)
    expect((await hit(ctx, 'a', 1, 60, now)).allowed).toBe(false)
  })

  it('stores the aligned window start', async () => {
    const { ctx, values } = counterContext()
    await hit(ctx, 'k', 3, 60, now)
    expect(values[0]!.window_start.toISOString()).toBe('2026-11-22T12:34:00.000Z')
  })

  it('allows the request when the database fails', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { ctx } = counterContext({ fail: true })
    expect(await hit(ctx, 'k', 3, 60, now)).toEqual({ allowed: true, remaining: 3, reset: 4 })
    expect(error).toHaveBeenCalledOnce()
  })

  it('refuses windows the cleanup could not handle', async () => {
    const { ctx } = counterContext()
    for (const windowSec of [0, -1, 1.5, MAX_WINDOW_SEC + 1]) {
      await expect(hit(ctx, 'k', 3, windowSec, now)).rejects.toThrow(RangeError)
    }
  })
})
