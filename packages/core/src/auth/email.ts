import { schema } from '@certifly/db'
import { eq } from 'drizzle-orm'
import type { Context } from '../context'
import { sha256 } from '../crypto'
import { AuthorizationError, NotFoundError, RateLimitError } from '../errors'
import type { Actor } from '../policies'
import { hit } from '../rate-limit'
import {
  assertEmailEnabled,
  consumeCode,
  consumeLinkToken,
  type EmailToken,
  issueEmailToken,
  normalizeEmail,
} from './email-tokens'
import { countUsers, decideNewUser, findPendingInvite, findUserByEmail, provisionUser, refusal, type User } from './provision'

/**
 * Sign-in mails per address: at most this many in one fixed window. Counted for every address
 * asked for, whether or not it may sign in, so the answer looks the same for both. The window
 * is short on purpose: a stranger who uses up someone's budget silences their mails only until
 * it ends, and codes already sent keep working.
 */
export const EMAIL_SIGNIN_BUDGET = { limit: 5, window_seconds: 10 * 60 }

/** Re-authentication mails per signed-in person, counted apart so sign-in requests by others cannot use them up. */
export const EMAIL_REAUTH_BUDGET = { limit: 5, window_seconds: 10 * 60 }

/**
 * Send a sign-in link and code. Resolves the same way whether or not the address may sign
 * in, and also once the address has had too many mails, so the response cannot be used to
 * find out who has an account. Two exceptions, both safe: on an instance without users there
 * is nobody to protect, so a missing or wrong setup token is reported, and a malformed
 * address is a validation error. Refused when the instance cannot send mail.
 */
export async function requestEmailSignin(ctx: Context, input: { email: string; setup_token?: string | null }): Promise<void> {
  assertEmailEnabled(ctx)
  const email = normalizeEmail(input.email)
  // Keyed by a hash: the table should not collect the addresses strangers typed in.
  const budget = await hit(ctx, `signin_email:${sha256(email)}`, EMAIL_SIGNIN_BUDGET.limit, EMAIL_SIGNIN_BUDGET.window_seconds)
  if (!budget.allowed) {
    console.warn(`[auth] sign-in mails to ${email} paused for ${budget.reset}s: too many requests for this address`)
    return
  }

  let setup_proven = false
  const existing = await findUserByEmail(ctx.db, email)
  if (existing) {
    if (existing.deleted_at) return
  } else {
    const user_count = await countUsers(ctx.db)
    const decision = decideNewUser({
      user_count,
      setup_token: ctx.setup_token,
      presented_token: input.setup_token,
      invite: await findPendingInvite(ctx.db, email),
      method: 'email',
    })
    if (!decision.allow) {
      if (decision.reason === 'invite_required') return
      throw refusal(decision.reason)
    }
    // Remember that the token was shown, so the person does not need it again at the code step.
    setup_proven = decision.via === 'bootstrap' && !!ctx.setup_token?.trim()
  }

  await issueEmailToken(ctx, { email, meta: setup_proven ? { setup_proven } : {} })
}

/**
 * Email the signed-in person a code to confirm it is them. The address is their own, so
 * running out of mails can be reported plainly.
 */
export async function requestEmailReauth(ctx: Context, actor: Actor): Promise<void> {
  if (actor.kind !== 'session') throw new AuthorizationError('Use a signed-in session for this')
  assertEmailEnabled(ctx)
  const [user] = await ctx.db.select({ email: schema.users.email }).from(schema.users).where(eq(schema.users.id, actor.id))
  if (!user) throw new NotFoundError('User not found')
  const budget = await hit(ctx, `reauth_email:${actor.id}`, EMAIL_REAUTH_BUDGET.limit, EMAIL_REAUTH_BUDGET.window_seconds)
  if (!budget.allowed) throw new RateLimitError()
  await issueEmailToken(ctx, { email: user.email, purpose: 'reauth' })
}

/** Exchange a sign-in link token for the user, consuming it. */
export async function verifyEmailToken(ctx: Context, token: string): Promise<User> {
  return signInWith(ctx, await consumeLinkToken(ctx, token))
}

/** Exchange an email + code for the user, consuming the token. */
export async function verifyEmailCode(ctx: Context, input: { email: string; code: string }): Promise<User> {
  return signInWith(ctx, await consumeCode(ctx, input))
}

/** The user a consumed token signs in, creating the account if the rules allow it. */
function signInWith(ctx: Context, token: EmailToken): Promise<User> {
  return provisionUser(ctx, { email: token.email }, { method: 'email', setup_proven: token.meta.setup_proven })
}
