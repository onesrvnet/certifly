import { type Executor, schema } from '@certifly/db'
import { and, count, eq, gt, isNull, sql } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from '../audit'
import type { Context } from '../context'
import { safeEqualString } from '../crypto'
import { AuthenticationError, AuthorizationError } from '../errors'
import type { Actor, Role } from '../policies'
import { normalizeEmail } from './email-tokens'

export type User = typeof schema.users.$inferSelect

export interface SigninProfile {
  email: string
  name?: string
  /** External identity, e.g. `{ provider: 'oidc', subject: '…' }`. */
  identity?: { provider: string; subject: string }
  /** Group names from the identity provider, for the admin mapping hook. */
  groups?: string[]
}

/** How the person proved who they are. Only OpenID Connect may create accounts nobody invited. */
export type SigninMethod = 'email' | 'oidc'

export interface ProvisionOptions {
  method: SigninMethod
  /** The setup token the person presented, for a first sign-in that did not go through an email code. */
  setup_token?: string | null
  /** The setup token was already checked when the email code was requested. */
  setup_proven?: boolean
  /**
   * Chooses the role of a new OpenID Connect user from the profile, e.g. `admin` for members
   * of certain groups. Return null for the default, `viewer`. Applies when the account is
   * created; later group changes do not change roles.
   */
  oidc_role?: (profile: SigninProfile) => Role | null | undefined
}

/** Arbitrary constant that serialises account creation, so two first sign-ins cannot both become admin. */
export const PROVISION_LOCK_ID = 727_003

export type NewUserDecision =
  | { allow: true; role: Role; via: 'bootstrap' | 'invite' | 'oidc' }
  | { allow: false; reason: 'setup_token_required' | 'setup_token_invalid' | 'invite_required' }

/**
 * Whether a person without an account may get one, and with which role.
 *
 * - On an instance without any user, the first sign-in becomes `admin`; when a setup token
 *   is configured it must also be presented (or have been proven at the email step).
 * - Afterwards only people with a pending invite (their invited role) and OpenID Connect
 *   users (`oidc_role`, default `viewer`) get in.
 */
export function decideNewUser(input: {
  user_count: number
  /** The configured SETUP_TOKEN; blank counts as not set. */
  setup_token?: string | null
  presented_token?: string | null
  setup_proven?: boolean
  invite?: { role: Role } | null
  method: SigninMethod
  oidc_role?: Role | null
}): NewUserDecision {
  if (input.user_count === 0) {
    const expected = input.setup_token?.trim() || null
    if (expected && !input.setup_proven) {
      if (!input.presented_token) return { allow: false, reason: 'setup_token_required' }
      if (!safeEqualString(input.presented_token.trim(), expected)) return { allow: false, reason: 'setup_token_invalid' }
    }
    return { allow: true, role: 'admin', via: 'bootstrap' }
  }
  if (input.invite) return { allow: true, role: input.invite.role, via: 'invite' }
  if (input.method === 'oidc') return { allow: true, role: input.oidc_role ?? 'viewer', via: 'oidc' }
  return { allow: false, reason: 'invite_required' }
}

/** The error for a refused decision. */
export function refusal(reason: Extract<NewUserDecision, { allow: false }>['reason']): AuthorizationError {
  switch (reason) {
    case 'setup_token_required':
      return new AuthorizationError('This instance needs its setup token for the first sign-in', 'setup_token_required')
    case 'setup_token_invalid':
      return new AuthorizationError('The setup token is not correct', 'setup_token_invalid')
    case 'invite_required':
      return new AuthorizationError('You need an invite to join', 'invite_required')
  }
}

/** Display name for a new account until its owner sets one. */
export function defaultName(email: string): string {
  return email.split('@')[0] ?? email
}

/** Number of accounts, deactivated ones included: removing every user does not reopen setup. */
export async function countUsers(db: Executor): Promise<number> {
  const [row] = await db.select({ n: count() }).from(schema.users)
  return row?.n ?? 0
}

/** The user with this email, active or deactivated. */
export async function findUserByEmail(db: Executor, email: string) {
  const [user] = await db.select().from(schema.users).where(eq(schema.users.email, email.trim().toLowerCase())).limit(1)
  return user
}

/** The newest invite for this email that is neither accepted nor expired. */
export async function findPendingInvite(db: Executor, email: string) {
  const [invite] = await db
    .select()
    .from(schema.invites)
    .where(
      and(
        eq(schema.invites.email, email.trim().toLowerCase()),
        isNull(schema.invites.accepted_at),
        gt(schema.invites.expires_at, new Date()),
      ),
    )
    .orderBy(sql`${schema.invites.created_at} desc`)
    .limit(1)
  return invite
}

/**
 * Find or create the user signing in. Existing accounts are matched by linked identity,
 * then by email; deactivated ones are refused. New accounts follow `decideNewUser`.
 */
export async function provisionUser(ctx: Context, profile: SigninProfile, options: ProvisionOptions): Promise<User> {
  const email = normalizeEmail(profile.email)

  const existing = await findExisting(ctx.db, profile, email)
  if (existing) return adopt(ctx.db, existing, profile)

  return withTransaction(ctx, async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(${PROVISION_LOCK_ID})`)
    // Someone else may have created it while we waited for the lock.
    const raced = await findExisting(tx, profile, email)
    if (raced) return adopt(tx, raced, profile)

    const invite = await findPendingInvite(tx, email)
    const decision = decideNewUser({
      user_count: await countUsers(tx),
      setup_token: ctx.setup_token,
      presented_token: options.setup_token,
      setup_proven: options.setup_proven,
      invite,
      method: options.method,
      oidc_role: options.oidc_role?.(profile),
    })
    if (!decision.allow) throw refusal(decision.reason)

    const [user] = await tx
      .insert(schema.users)
      .values({ email, name: profile.name?.trim() || defaultName(email), role: decision.role })
      .returning()
    if (invite) await tx.update(schema.invites).set({ accepted_at: new Date() }).where(eq(schema.invites.id, invite.id))
    if (profile.identity) await linkIdentity(tx, user!.id, profile.identity)
    await recordEvent(
      ctx,
      eventFor({ id: user!.id, role: user!.role, kind: 'session', reauth_at: null }, 'users.create', { type: 'user', id: user!.id }, { role: user!.role, via: decision.via }),
      tx,
    )
    return user!
  })
}

/**
 * Check that an external sign-in is the signed-in person, for re-authenticating with the
 * identity provider. The identity is matched as sign-in matches it (linked identity first,
 * then the verified email address); an identity linked to someone else never counts.
 */
export async function confirmIdentity(ctx: Context, actor: Actor, profile: SigninProfile): Promise<void> {
  const user = await findExisting(ctx.db, profile, normalizeEmail(profile.email))
  if (!user || user.id !== actor.id || user.deleted_at) {
    throw new AuthenticationError('You signed in with an account that is not this one', 'reauth_mismatch')
  }
}

async function findExisting(db: Executor, profile: SigninProfile, email: string): Promise<User | undefined> {
  if (profile.identity) {
    const [linked] = await db
      .select({ user: schema.users })
      .from(schema.userIdentities)
      .innerJoin(schema.users, eq(schema.users.id, schema.userIdentities.user_id))
      .where(
        and(
          eq(schema.userIdentities.provider, profile.identity.provider),
          eq(schema.userIdentities.provider_user_id, profile.identity.subject),
        ),
      )
      .limit(1)
    if (linked) return linked.user
  }
  return findUserByEmail(db, email)
}

/** Let an existing account sign in, linking a new identity to it. */
async function adopt(db: Executor, user: User, profile: SigninProfile): Promise<User> {
  if (user.deleted_at) throw new AuthenticationError('This account has been deactivated', 'account_deactivated')
  if (profile.identity) await linkIdentity(db, user.id, profile.identity)
  return user
}

async function linkIdentity(db: Executor, userId: string, identity: { provider: string; subject: string }) {
  await db
    .insert(schema.userIdentities)
    .values({ user_id: userId, provider: identity.provider, provider_user_id: identity.subject })
    .onConflictDoNothing()
}
