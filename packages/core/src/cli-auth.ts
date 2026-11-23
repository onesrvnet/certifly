import { createHash, randomInt } from 'node:crypto'
import { schema } from '@certifly/db'
import { and, desc, eq, gt, isNull } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import type { Context } from './context'
import { randomToken, safeEqualString, sha256 } from './crypto'
import { AppError, AuthorizationError, NotFoundError, ValidationError } from './errors'
import type { Actor } from './policies'
import { stripControlCharacters } from './text'
import { ensureUsername } from './usernames'

/** Prefix of command-line session tokens, so secret scanners recognise them. */
export const CLI_TOKEN_PREFIX = 'cfc_'
export const CLI_LOGIN_TTL_MS = 10 * 60 * 1000
export const CLI_SESSION_TTL_MS = 12 * 60 * 60 * 1000
export const CLI_POLL_INTERVAL_SECONDS = 5

/** Letters without vowels or lookalikes, so a code cannot spell a word and is easy to read out. */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ'

export type CliLoginRow = typeof schema.cliLogins.$inferSelect
export type CliSessionRow = typeof schema.cliSessions.$inferSelect

function userCode(): string {
  const part = () => Array.from({ length: 4 }, () => USER_CODE_ALPHABET[randomInt(USER_CODE_ALPHABET.length)]).join('')
  return `${part()}-${part()}`
}

const text = (value: unknown, field: string, max: number): string => {
  const v = stripControlCharacters(String(value ?? '')).trim()
  if (!v || v.length > max) throw new ValidationError(`${field} must be 1 to ${max} characters`)
  return v
}

/** base64url of the SHA-256 of the code verifier, the PKCE `S256` challenge. */
export function challengeFor(code_verifier: string): string {
  return createHash('sha256').update(code_verifier).digest('base64url')
}

export interface StartCliLoginInput {
  code_challenge: string
  machine: { hostname: string; os: string }
  ip?: string | null
}

/** Start a command-line sign-in. Nothing is trusted yet: the person approves it in the browser. */
export async function startCliLogin(ctx: Context, input: StartCliLoginInput) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(String(input.code_challenge ?? ''))) throw new ValidationError('code_challenge must be the base64url SHA-256 of the code verifier', 'invalid_code_challenge')
  const hostname = text(input.machine?.hostname, 'machine.hostname', 100)
  const os = text(input.machine?.os, 'machine.os', 50)
  const device_code = randomToken(32)
  const user_code = userCode()
  const expires_at = new Date(Date.now() + CLI_LOGIN_TTL_MS)
  const [row] = await ctx.db
    .insert(schema.cliLogins)
    .values({ device_code_hash: sha256(device_code), user_code, code_challenge: input.code_challenge, machine_hostname: hostname, machine_os: os, expires_at, ip: input.ip ?? null })
    .returning()
  return {
    login_id: row!.id,
    device_code,
    user_code,
    browser_url: `${ctx.base_url.replace(/\/$/, '')}/cli/login/${row!.id}`,
    interval_seconds: CLI_POLL_INTERVAL_SECONDS,
    expires_at,
  }
}

/** What the confirm screen shows. Needs a signed-in person; only pending, unexpired logins are shown. */
export async function getCliLogin(ctx: Context, login_id: string): Promise<CliLoginRow> {
  const [row] = await ctx.db.select().from(schema.cliLogins).where(eq(schema.cliLogins.id, login_id))
  if (!row || row.expires_at <= new Date() || row.consumed_at) throw new NotFoundError('This sign-in has expired or does not exist', 'cli_login_expired')
  return row
}

function webSession(actor: Actor) {
  // Only the browser session may approve: a leaked API key or CLI token must not mint more tokens.
  if (actor.kind !== 'session') throw new AuthorizationError('Use a signed-in session for this')
}

async function decide(ctx: Context, actor: Actor, login_id: string, status: 'approved' | 'denied') {
  webSession(actor)
  return withTransaction(ctx, async (tx) => {
    const [row] = await tx.select().from(schema.cliLogins).where(eq(schema.cliLogins.id, login_id)).for('update')
    if (!row || row.expires_at <= new Date() || row.consumed_at) throw new NotFoundError('This sign-in has expired or does not exist', 'cli_login_expired')
    if (row.status !== 'pending') return row
    const [updated] = await tx.update(schema.cliLogins).set({ status, user_id: status === 'approved' ? actor.id : null }).where(eq(schema.cliLogins.id, login_id)).returning()
    await recordEvent(ctx, eventFor(actor, status === 'approved' ? 'cli_logins.approve' : 'cli_logins.deny', { type: 'cli_login', id: login_id }, { machine: `${row.machine_hostname} (${row.machine_os})`, user_code: row.user_code }), tx)
    return updated!
  })
}

export const approveCliLogin = (ctx: Context, actor: Actor, login_id: string) => decide(ctx, actor, login_id, 'approved')
export const denyCliLogin = (ctx: Context, actor: Actor, login_id: string) => decide(ctx, actor, login_id, 'denied')

export type PollResult =
  | { status: 'pending' }
  | { status: 'approved'; token: string; expires_at: Date; user: { id: string; name: string; email: string; username: string } }

/**
 * The CLI asks whether the person approved. The code verifier must match the challenge sent at
 * the start. An approved login hands out its token once; a second poll finds it spent.
 */
export async function pollCliLogin(ctx: Context, input: { device_code: string; code_verifier: string }): Promise<PollResult> {
  const expired = () => new AppError(410, 'cli_login_expired', 'This sign-in has expired')
  const [row] = await ctx.db.select().from(schema.cliLogins).where(eq(schema.cliLogins.device_code_hash, sha256(String(input.device_code ?? ''))))
  if (!row) throw expired()
  if (!safeEqualString(challengeFor(String(input.code_verifier ?? '')), row.code_challenge)) throw new AppError(400, 'invalid_code_verifier', 'The code verifier does not match')
  if (row.expires_at <= new Date() || row.consumed_at) throw expired()
  if (row.status === 'denied') throw new AppError(403, 'cli_login_denied', 'The sign-in was denied')

  const now = new Date()
  const tooFast = row.last_poll_at && now.getTime() - row.last_poll_at.getTime() < (CLI_POLL_INTERVAL_SECONDS - 1) * 1000
  await ctx.db.update(schema.cliLogins).set({ last_poll_at: now }).where(eq(schema.cliLogins.id, row.id))
  if (tooFast) throw new AppError(429, 'slow_down', 'Poll less often')
  if (row.status === 'pending') return { status: 'pending' }

  return withTransaction(ctx, async (tx) => {
    const [fresh] = await tx.select().from(schema.cliLogins).where(eq(schema.cliLogins.id, row.id)).for('update')
    if (!fresh || fresh.consumed_at || !fresh.user_id) throw expired()
    const [user] = await tx.select().from(schema.users).where(and(eq(schema.users.id, fresh.user_id), isNull(schema.users.deleted_at)))
    if (!user) throw new AppError(403, 'cli_login_denied', 'The sign-in was denied')
    const token = `${CLI_TOKEN_PREFIX}${randomToken(30)}`
    const expires_at = new Date(now.getTime() + CLI_SESSION_TTL_MS)
    const [session] = await tx
      .insert(schema.cliSessions)
      .values({ user_id: user.id, token_hash: sha256(token), machine_hostname: fresh.machine_hostname, machine_os: fresh.machine_os, expires_at })
      .returning()
    await tx.update(schema.cliLogins).set({ consumed_at: now }).where(eq(schema.cliLogins.id, fresh.id))
    const username = await ensureUsername(tx, user)
    await recordEvent(
      ctx,
      eventFor({ id: user.id, role: user.role, kind: 'cli', cli_session_id: session!.id, ip: fresh.ip, reauth_at: null }, 'cli_sessions.create', { type: 'cli_session', id: session!.id }, { machine: `${fresh.machine_hostname} (${fresh.machine_os})` }),
      tx,
    )
    return { status: 'approved' as const, token, expires_at, user: { id: user.id, name: user.name, email: user.email, username } }
  })
}

/** The active user behind a CLI token, or null. */
export async function getCliSessionUser(ctx: Context, token: string) {
  if (!token.startsWith(CLI_TOKEN_PREFIX)) return null
  const [row] = await ctx.db
    .select({ session: schema.cliSessions, user: schema.users })
    .from(schema.cliSessions)
    .innerJoin(schema.users, eq(schema.users.id, schema.cliSessions.user_id))
    .where(and(eq(schema.cliSessions.token_hash, sha256(token)), gt(schema.cliSessions.expires_at, new Date()), isNull(schema.cliSessions.revoked_at), isNull(schema.users.deleted_at)))
    .limit(1)
  if (!row) return null
  if (!row.session.last_used_at || Date.now() - row.session.last_used_at.getTime() > 60_000) {
    await ctx.db.update(schema.cliSessions).set({ last_used_at: new Date() }).where(eq(schema.cliSessions.id, row.session.id))
  }
  return row
}

/** The person's own live CLI sessions. */
export async function listCliSessions(ctx: Context, actor: Actor): Promise<CliSessionRow[]> {
  return ctx.db
    .select()
    .from(schema.cliSessions)
    .where(and(eq(schema.cliSessions.user_id, actor.id), gt(schema.cliSessions.expires_at, new Date()), isNull(schema.cliSessions.revoked_at)))
    .orderBy(desc(schema.cliSessions.created_at), desc(schema.cliSessions.id))
}

/**
 * Sign a CLI session out. A CLI token ends itself (no id needed); a person with a browser
 * session or API key names one of their own sessions. Other people's sessions are not found.
 */
export async function revokeCliSession(ctx: Context, actor: Actor, id?: string): Promise<void> {
  const target = id ?? actor.cli_session_id
  if (!target) throw new ValidationError('id is required', 'validation_error')
  if (actor.kind === 'cli' && id && id !== actor.cli_session_id) throw new NotFoundError('Session not found')
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx
      .update(schema.cliSessions)
      .set({ revoked_at: new Date() })
      .where(and(eq(schema.cliSessions.id, target), eq(schema.cliSessions.user_id, actor.id), isNull(schema.cliSessions.revoked_at)))
      .returning({ id: schema.cliSessions.id })
    if (!row) throw new NotFoundError('Session not found')
    await recordEvent(ctx, eventFor(actor, 'cli_sessions.delete', { type: 'cli_session', id: target }), tx)
  })
}
