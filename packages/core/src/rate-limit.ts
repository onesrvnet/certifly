import { schema } from '@certifly/db'
import { sql } from 'drizzle-orm'
import type { Context } from './context'

/** The longest window `hit` accepts; the cleanup job deletes counters older than this. */
export const MAX_WINDOW_SEC = 24 * 60 * 60

export interface RateLimitResult {
  allowed: boolean
  /** Requests left in this window. */
  remaining: number
  /** Seconds until the window ends and the count starts over. */
  reset: number
}

/** The fixed window that `nowMs` falls into: its start, and the seconds left in it. */
export function windowOf(nowMs: number, windowSec: number) {
  const nowSec = Math.floor(nowMs / 1000)
  const startSec = nowSec - (nowSec % windowSec)
  return { start: new Date(startSec * 1000), reset: startSec + windowSec - nowSec }
}

/** What a count means for a limit: the request that makes the count exceed the limit is refused. */
export function evaluate(count: number, limit: number, reset: number): RateLimitResult {
  return { allowed: count <= limit, remaining: Math.max(0, limit - count), reset }
}

/**
 * Count one request against `key` in a fixed window of `windowSec` seconds. The counter is
 * one atomic upsert, so concurrent requests on any instance are counted exactly. If the
 * database fails the request is allowed and the error logged: an outage of the limiter
 * must not lock everyone out.
 */
export async function hit(ctx: Context, key: string, limit: number, windowSec: number, now = new Date()): Promise<RateLimitResult> {
  if (!Number.isInteger(windowSec) || windowSec < 1 || windowSec > MAX_WINDOW_SEC) {
    throw new RangeError(`Rate-limit window must be 1 to ${MAX_WINDOW_SEC} seconds`)
  }
  const { start, reset } = windowOf(now.getTime(), windowSec)
  try {
    const [row] = await ctx.db
      .insert(schema.rateLimits)
      .values({ key, window_start: start, count: 1 })
      .onConflictDoUpdate({
        target: [schema.rateLimits.key, schema.rateLimits.window_start],
        set: { count: sql`${schema.rateLimits.count} + 1` },
      })
      .returning({ count: schema.rateLimits.count })
    return evaluate(row!.count, limit, reset)
  } catch (error) {
    console.error('[rate-limit] database unavailable, allowing request', error)
    return { allowed: true, remaining: limit, reset }
  }
}
