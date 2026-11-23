import { schema } from '@certifly/db'
import { eq } from 'drizzle-orm'
import { eventFor, recordEvent } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { ValidationError } from './errors'
import { type Actor, authorize, settingsPolicy } from './policies'

/** All instance settings as a key/value record. */
export async function listSettings(ctx: Context, actor: Actor): Promise<Record<string, unknown>> {
  authorize(settingsPolicy, actor, 'read', undefined)
  const rows = await ctx.db.select().from(schema.instanceSettings)
  return Object.fromEntries(rows.map((row) => [row.key, row.value]))
}

/** One setting, or null when it was never set. */
export async function getSetting(ctx: Context, actor: Actor, key: string): Promise<unknown> {
  authorize(settingsPolicy, actor, 'read', undefined)
  const [row] = await ctx.db.select().from(schema.instanceSettings).where(eq(schema.instanceSettings.key, key))
  return row?.value ?? null
}

/**
 * Set or replace one setting. `null` removes it, so it reads as never set again (`getSetting`
 * answers null for both). Only the key is recorded in the audit log, never the value. Needs a
 * recent re-authentication.
 */
export async function setSetting(ctx: Context, actor: Actor, key: string, value: unknown): Promise<void> {
  authorize(settingsPolicy, actor, 'update', undefined)
  assertStepUp(actor)
  if (!/^[a-z][a-z0-9_.]{0,63}$/.test(key)) throw new ValidationError('Setting keys are lowercase words joined by dots or underscores')
  if (value === undefined) throw new ValidationError('A setting needs a value')
  if (value === null) {
    await ctx.db.delete(schema.instanceSettings).where(eq(schema.instanceSettings.key, key))
    await recordEvent(ctx, eventFor(actor, 'settings.update', undefined, { key, removed: true }))
    return
  }
  await ctx.db
    .insert(schema.instanceSettings)
    .values({ key, value })
    .onConflictDoUpdate({ target: schema.instanceSettings.key, set: { value } })
  await recordEvent(ctx, eventFor(actor, 'settings.update', undefined, { key }))
}
