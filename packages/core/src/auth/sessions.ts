import { type Executor, schema } from '@certifly/db'
import { and, desc, eq, gt, isNull } from 'drizzle-orm'
import { eventFor, recordEvent } from '../audit'
import type { Context } from '../context'
import { AuthenticationError, AuthorizationError, NotFoundError } from '../errors'
import { type Actor, authorize, type Role, userPolicy } from '../policies'

export type SessionRow = typeof schema.sessions.$inferSelect

export const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000
/** A session unused for this long ends, whatever is left of its lifetime. */
export const SESSION_IDLE_MS = 14 * 24 * 60 * 60 * 1000
/** Only touch last_active_at this often to avoid a write on every request. */
const ACTIVITY_WRITE_INTERVAL_MS = 5 * 60 * 1000
/** How recently someone must have proven who they are for sensitive actions. */
export const STEP_UP_MAX_AGE_MS = 10 * 60 * 1000

const SESSION_ONLY = 'Use a signed-in session for this'

/**
 * Start a session. Signing in just proved who the person is, so the session counts as
 * freshly re-authenticated.
 */
export async function createSession(
  ctx: Context,
  userId: string,
  meta: { user_agent?: string; ip_address?: string; method?: string } = {},
) {
  const now = new Date()
  const { method, ...rest } = meta
  const [session] = await ctx.db
    .insert(schema.sessions)
    .values({ user_id: userId, ...rest, reauth_at: now, expires_at: new Date(now.getTime() + SESSION_TTL_MS) })
    .returning()
  await ctx.db.update(schema.users).set({ last_signed_in_at: now }).where(eq(schema.users.id, userId))
  await recordEvent(ctx, {
    actor_type: 'user',
    actor_id: userId,
    name: 'sessions.create',
    subject_type: 'session',
    subject_id: session!.id,
    data: method ? { method } : {},
    ip: meta.ip_address ?? null,
  })
  return session!
}

/** Sessions that have neither reached their end nor been left unused for SESSION_IDLE_MS. */
export const liveSession = (now: Date) => and(gt(schema.sessions.expires_at, now), gt(schema.sessions.last_active_at, new Date(now.getTime() - SESSION_IDLE_MS)))

/**
 * Load the user behind a session id. Returns null for unknown, expired, idle or revoked
 * sessions and for deactivated users.
 */
export async function getSessionUser(ctx: Context, sessionId: string) {
  const [found] = await ctx.db
    .select({ session: schema.sessions, user: schema.users })
    .from(schema.sessions)
    .innerJoin(schema.users, eq(schema.users.id, schema.sessions.user_id))
    .where(and(eq(schema.sessions.id, sessionId), liveSession(new Date()), isNull(schema.users.deleted_at)))
    .limit(1)
  if (!found) return null

  const now = Date.now()
  const stale = now - found.session.last_active_at.getTime() > ACTIVITY_WRITE_INTERVAL_MS
  if (!stale && found.user.last_active_at) return found
  const at = new Date(now)
  await ctx.db.update(schema.sessions).set({ last_active_at: at }).where(eq(schema.sessions.id, sessionId))
  const [user] = await ctx.db
    .update(schema.users)
    .set({ last_active_at: at })
    .where(eq(schema.users.id, found.user.id))
    .returning()
  return { session: { ...found.session, last_active_at: at }, user: user! }
}

export async function revokeSession(ctx: Context, sessionId: string) {
  await ctx.db.delete(schema.sessions).where(eq(schema.sessions.id, sessionId))
}

/** End every session of a user, e.g. when an admin deactivates them. */
export async function revokeUserSessions(ctx: Context, actor: Actor, user: { id: string; role: Role }, db: Executor = ctx.db) {
  authorize(userPolicy, actor, 'deactivate', user)
  await db.delete(schema.sessions).where(eq(schema.sessions.user_id, user.id))
}

/** The actor's own live sessions, most recently active first. */
export async function listUserSessions(ctx: Context, actor: Actor, now = new Date()): Promise<SessionRow[]> {
  return ctx.db
    .select()
    .from(schema.sessions)
    .where(and(eq(schema.sessions.user_id, actor.id), liveSession(now)))
    .orderBy(desc(schema.sessions.last_active_at), desc(schema.sessions.id))
}

/** End one of the actor's own sessions. Someone else's session is reported as not found. */
export async function revokeOwnSession(ctx: Context, actor: Actor, id: string) {
  const [session] = await ctx.db
    .delete(schema.sessions)
    .where(and(eq(schema.sessions.id, id), eq(schema.sessions.user_id, actor.id)))
    .returning({ id: schema.sessions.id })
  if (!session) throw new NotFoundError('Session not found')
  await recordEvent(ctx, eventFor(actor, 'sessions.delete', { type: 'session', id }))
}

/**
 * Remember that the person proved who they are again in this session. Only the actor's own
 * session counts; anything else is reported as not found.
 */
export async function markReauthenticated(ctx: Context, actor: Actor, sessionId: string, at = new Date()) {
  if (actor.kind !== 'session') throw new AuthorizationError(SESSION_ONLY)
  const [session] = await ctx.db
    .update(schema.sessions)
    .set({ reauth_at: at })
    .where(and(eq(schema.sessions.id, sessionId), eq(schema.sessions.user_id, actor.id)))
    .returning({ id: schema.sessions.id })
  if (!session) throw new NotFoundError('Session not found')
}

/**
 * Step-up check for sensitive actions: the session must have been re-authenticated within
 * `maxAgeMs`. API keys have no session (null) and no `reauth_at`, so they always fail.
 */
export function assertRecentReauth(
  session: { reauth_at: Date | null } | null | undefined,
  maxAgeMs: number = STEP_UP_MAX_AGE_MS,
  now: Date = new Date(),
): void {
  const at = session?.reauth_at
  if (!at || now.getTime() - at.getTime() > maxAgeMs) {
    throw new AuthorizationError('Confirm it is you again to do this', 'reauth_required')
  }
}

/** How someone proved who they are again. */
export type ReauthMethod = 'email' | 'passkey' | 'oidc'

/** Record that the actor re-authenticated their session and note it in the audit log. */
export async function reauthenticateSession(ctx: Context, actor: Actor, sessionId: string, method: ReauthMethod, at = new Date()) {
  await markReauthenticated(ctx, actor, sessionId, at)
  await recordEvent(ctx, eventFor(actor, 'sessions.reauthenticate', { type: 'session', id: sessionId }, { method }))
  return at
}

/**
 * Step-up for changes to credentials, people, invites and settings: the actor must be an
 * interactive session that re-authenticated within the last 10 minutes. API keys never pass,
 * so a leaked key can neither add a way in nor change who has access. Call it after
 * `authorize`, so someone who may not do the action at all is told that instead.
 */
export function assertStepUp(actor: Actor, now: Date = new Date()): void {
  if (actor.kind !== 'session') throw new AuthorizationError(SESSION_ONLY)
  assertRecentReauth(actor, STEP_UP_MAX_AGE_MS, now)
}

/** How long after the start of a provider re-authentication its sign-in may have happened, for clock drift. */
const AUTH_TIME_SKEW_MS = 60 * 1000

/**
 * Whether an identity provider's `auth_time` shows a sign-in made for this re-authentication:
 * after the redirect to the provider started (allowing for clock drift), and not in the future.
 */
export function assertFreshAuthTime(auth_time: number | undefined, started_at: Date, now: Date = new Date()): void {
  const at = typeof auth_time === 'number' && Number.isFinite(auth_time) ? auth_time * 1000 : null
  if (at === null || at < started_at.getTime() - AUTH_TIME_SKEW_MS || at > now.getTime() + AUTH_TIME_SKEW_MS) {
    throw new AuthenticationError('The provider did not confirm a fresh sign-in', 'reauth_stale')
  }
}

/** Whether the session counts as freshly re-authenticated, for showing it in the UI. */
export function isRecentlyReauthenticated(
  session: { reauth_at: Date | null } | null | undefined,
  maxAgeMs: number = STEP_UP_MAX_AGE_MS,
  now: Date = new Date(),
): boolean {
  try {
    assertRecentReauth(session, maxAgeMs, now)
    return true
  } catch {
    return false
  }
}
