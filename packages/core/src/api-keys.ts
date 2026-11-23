import { schema } from '@certifly/db'
import { and, desc, eq, gt, isNull, or } from 'drizzle-orm'
import { eventFor, recordEvent } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { randomToken, sha256 } from './crypto'
import { NotFoundError, ValidationError } from './errors'
import { type Actor, apiKeyPolicy, authorize } from './policies'

/** Prefix that makes tokens recognisable, e.g. for secret scanning. */
export const API_KEY_PREFIX = 'cfy_'

export type ApiKeyRow = typeof schema.apiKeys.$inferSelect

/** Create a key for the actor. The secret is returned once and never stored. Needs a recent re-authentication. */
export async function createApiKey(ctx: Context, actor: Actor, input: { name: string; expires_at?: Date | null }) {
  authorize(apiKeyPolicy, actor, 'create', { user_id: actor.id })
  assertStepUp(actor)
  const name = input.name.trim()
  if (!name) throw new ValidationError('Name cannot be empty')
  if (input.expires_at && input.expires_at.getTime() <= Date.now()) throw new ValidationError('Expiry must be in the future')

  const secret = `${API_KEY_PREFIX}${randomToken(30)}`
  const [key] = await ctx.db
    .insert(schema.apiKeys)
    .values({ user_id: actor.id, name, secret_hash: sha256(secret), last4: secret.slice(-4), expires_at: input.expires_at ?? null })
    .returning()
  await recordEvent(ctx, eventFor(actor, 'api_keys.create', { type: 'api_key', id: key!.id }, { name }))
  return { key: key!, secret }
}

export async function listApiKeys(ctx: Context, actor: Actor) {
  authorize(apiKeyPolicy, actor, 'read', { user_id: actor.id })
  return ctx.db
    .select()
    .from(schema.apiKeys)
    .where(eq(schema.apiKeys.user_id, actor.id))
    .orderBy(desc(schema.apiKeys.created_at))
}

/** Delete one of the actor's own keys; other people's keys are reported as not found. */
export async function deleteApiKey(ctx: Context, actor: Actor, id: string) {
  const [key] = await ctx.db.select().from(schema.apiKeys).where(eq(schema.apiKeys.id, id)).limit(1)
  if (!key || !apiKeyPolicy.can(actor, 'read', key)) throw new NotFoundError('API key not found')
  authorize(apiKeyPolicy, actor, 'delete', key)
  await ctx.db.delete(schema.apiKeys).where(eq(schema.apiKeys.id, key.id))
  await recordEvent(ctx, eventFor(actor, 'api_keys.delete', { type: 'api_key', id: key.id }, { name: key.name }))
}

/** Resolve the active user behind a bearer token, or null. */
export async function getApiKeyUser(ctx: Context, secret: string) {
  if (!secret.startsWith(API_KEY_PREFIX)) return null
  const [row] = await ctx.db
    .select({ key: schema.apiKeys, user: schema.users })
    .from(schema.apiKeys)
    .innerJoin(schema.users, eq(schema.users.id, schema.apiKeys.user_id))
    .where(
      and(
        eq(schema.apiKeys.secret_hash, sha256(secret)),
        or(isNull(schema.apiKeys.expires_at), gt(schema.apiKeys.expires_at, new Date())),
        isNull(schema.users.deleted_at),
      ),
    )
    .limit(1)
  if (!row) return null
  if (!row.key.last_used_at || Date.now() - row.key.last_used_at.getTime() > 60_000) {
    await ctx.db.update(schema.apiKeys).set({ last_used_at: new Date() }).where(eq(schema.apiKeys.id, row.key.id))
  }
  return row
}
