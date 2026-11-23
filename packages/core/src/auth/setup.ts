import { type Executor, schema } from '@certifly/db'
import { and, eq, sql } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from '../audit'
import type { Context } from '../context'
import { safeEqualString } from '../crypto'
import { AuthorizationError, ConflictError } from '../errors'
import { normalizeEmail } from './email-tokens'
import { defaultName, PROVISION_LOCK_ID, type User } from './provision'

/**
 * Setting up an instance that cannot send mail: whoever holds the SETUP_TOKEN creates the
 * first admin directly, and is then asked to add a passkey so they can sign in again. Until
 * that admin has a passkey or a linked identity, the token may be used again to get back into
 * the same account, so leaving before adding one does not lock everybody out.
 *
 * Which account the token created is read from the audit log (`users.create` with
 * `method: 'setup_token'`). The log is append-only, so that record cannot change later, and a
 * `passkeys.create` entry stays even if the passkey is removed again: setup never reopens.
 */

/**
 * How the instance gets its first admin right now, for the sign-in page; null once it has one.
 *
 * - `email`: the first person to sign in by email becomes admin (with the setup token when one is set).
 * - `token`: the instance cannot send mail and has a setup token; the token holder creates the
 *   admin with `bootstrapAdmin`, or gets back into it while setup is unfinished.
 * - `oidc_only`: no mail and no setup token; the first sign-in with the identity provider becomes admin.
 * - `unavailable`: none of these is configured, so nobody can set the instance up yet.
 */
export type SetupMethod = 'email' | 'token' | 'oidc_only' | 'unavailable'

type TokenSetupState = { kind: 'empty' } | { kind: 'pending'; user: User } | { kind: 'closed' }

const configuredToken = (ctx: Context) => ctx.setup_token?.trim() || null

/** Token setup is off when the instance can send mail (setup then goes by email) or has no token. */
const tokenSetupEnabled = (ctx: Context) => !ctx.mailer.delivers && !!configuredToken(ctx)

export async function setupMethod(ctx: Context, options: { oidc_enabled: boolean }): Promise<SetupMethod | null> {
  const state = await tokenSetupState(ctx.db)
  if (state.kind === 'empty') {
    if (ctx.mailer.delivers) return 'email'
    if (configuredToken(ctx)) return 'token'
    return options.oidc_enabled ? 'oidc_only' : 'unavailable'
  }
  // Once someone has an account, only an unfinished token setup is left to do.
  return state.kind === 'pending' && tokenSetupEnabled(ctx) ? 'token' : null
}

/**
 * Create the first admin with the setup token, or sign back into it while setup is unfinished.
 *
 * Refused (`token_setup_unavailable`) when the instance can send mail or has no setup token.
 * A wrong token and a finished setup get the same answer (`setup_token_invalid`) by the same
 * path, so after setup nobody can find out whether a guessed token is right. While setup is
 * unfinished, only the address it was started with is accepted (`setup_email_mismatch`): the
 * token never makes a second account or replaces the first.
 */
export async function bootstrapAdmin(ctx: Context, input: { setup_token: string; email: string; name?: string }): Promise<User> {
  const expected = configuredToken(ctx)
  if (!expected || ctx.mailer.delivers) throw unavailable()
  const email = normalizeEmail(input.email)

  const tokenOk = safeEqualString(input.setup_token.trim(), expected)
  const seen = await tokenSetupState(ctx.db)
  if (!tokenOk || seen.kind === 'closed') throw invalidToken()

  // The same lock as account creation on sign-in, so this and a first sign-in cannot both make an admin.
  return withTransaction(ctx, async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(${PROVISION_LOCK_ID})`)
    const state = await tokenSetupState(tx)
    if (state.kind === 'closed') throw invalidToken()
    if (state.kind === 'pending') {
      if (state.user.email !== email) {
        throw new ConflictError('Setup was started with a different email address. Use that address to continue.', 'setup_email_mismatch')
      }
      return state.user
    }

    const [user] = await tx
      .insert(schema.users)
      .values({ email, name: input.name?.trim() || defaultName(email), role: 'admin' })
      .returning()
    await recordEvent(
      ctx,
      eventFor(
        { id: user!.id, role: user!.role, kind: 'session', reauth_at: null },
        'users.create',
        { type: 'user', id: user!.id },
        { role: user!.role, via: 'bootstrap', method: 'setup_token' },
      ),
      tx,
    )
    return user!
  })
}

/**
 * Where token setup stands. Open while nobody has an account, or while the only account is
 * the one the token created and it has never had a way to sign in again. Deactivated
 * accounts count, so removing everyone does not reopen setup.
 */
async function tokenSetupState(db: Executor): Promise<TokenSetupState> {
  const users = await db.select().from(schema.users).limit(2)
  if (users.length === 0) return { kind: 'empty' }
  const [user] = users
  if (users.length > 1 || !user || user.deleted_at || !(await awaitingFirstCredential(db, user.id))) return { kind: 'closed' }
  return { kind: 'pending', user }
}

async function awaitingFirstCredential(db: Executor, userId: string): Promise<boolean> {
  // Cheapest and most common answer first: an admin with a passkey is done.
  const [passkey] = await db.select({ id: schema.passkeys.id }).from(schema.passkeys).where(eq(schema.passkeys.user_id, userId)).limit(1)
  if (passkey) return false
  const [identity] = await db
    .select({ id: schema.userIdentities.id })
    .from(schema.userIdentities)
    .where(eq(schema.userIdentities.user_id, userId))
    .limit(1)
  if (identity) return false
  const events = schema.events
  const [created] = await db
    .select({ id: events.id })
    .from(events)
    .where(
      and(
        eq(events.name, 'users.create'),
        eq(events.subject_type, 'user'),
        eq(events.subject_id, userId),
        sql`${events.data}->>'method' = 'setup_token'`,
      ),
    )
    .limit(1)
  if (!created) return false
  const [hadPasskey] = await db
    .select({ id: events.id })
    .from(events)
    .where(and(eq(events.name, 'passkeys.create'), eq(events.actor_type, 'user'), eq(events.actor_id, userId)))
    .limit(1)
  return !hadPasskey
}

function unavailable() {
  return new AuthorizationError('Setting up with the setup token is not available on this instance', 'token_setup_unavailable')
}

function invalidToken() {
  return new AuthorizationError('The setup token is not correct, or setup is already finished', 'setup_token_invalid')
}
