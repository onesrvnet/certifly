import { schema } from '@certifly/db'
import { and, eq, gt, isNotNull, isNull, lte, sql, type SQL } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { normalizeEmail } from './auth/email-tokens'
import { provisionUser, type User } from './auth/provision'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { type CursorInput, keyset, paged } from './cursor'
import { randomToken, sha256 } from './crypto'
import { ConflictError, isUniqueViolation, NotFoundError } from './errors'
import { inviteMail } from './mail-templates'
import { type Actor, authorize, invitePolicy, type Role } from './policies'

export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000

/** Arbitrary constant that, with a hash of the address, serialises invites for one address. */
const INVITE_LOCK_ID = 727_005

export type InviteRow = typeof schema.invites.$inferSelect

export type InviteStatus = 'pending' | 'accepted' | 'expired'

export function inviteStatus(invite: Pick<InviteRow, 'accepted_at' | 'expires_at'>, now = new Date()): InviteStatus {
  if (invite.accepted_at) return 'accepted'
  return invite.expires_at.getTime() <= now.getTime() ? 'expired' : 'pending'
}

/** The unique index that allows one pending invite per address. */
const PENDING_INVITE_INDEX = 'invites_pending_email_idx'

/**
 * Invite an email address to join with a role, and email them a link (`/invite?token=…`).
 * An earlier pending invite for the same address is replaced. The token is returned once;
 * only its hash is stored. When the instance cannot send mail, nothing is queued and the
 * caller gets the link (`mailed: false`) to hand over itself. Needs a recent re-authentication.
 */
export async function createInvite(ctx: Context, actor: Actor, input: { email: string; role: Role }) {
  authorize(invitePolicy, actor, 'create', undefined)
  assertStepUp(actor)
  const email = normalizeEmail(input.email)
  const [existing] = await ctx.db.select({ id: schema.users.id }).from(schema.users).where(eq(schema.users.email, email))
  if (existing) throw new ConflictError('Someone with this email address already has an account', 'user_exists')

  const token = randomToken()
  const invite = await withTransaction(ctx, async (tx) => {
    // Invites for one address take turns, so each replaces the one before; the unique index
    // on pending invites backs this up.
    await tx.execute(sql`select pg_advisory_xact_lock(${INVITE_LOCK_ID}, hashtext(${email}))`)
    await tx.delete(schema.invites).where(and(eq(schema.invites.email, email), isNull(schema.invites.accepted_at)))
    const [row] = await tx
      .insert(schema.invites)
      .values({
        email,
        role: input.role,
        invited_by_id: actor.id,
        token_hash: sha256(token),
        expires_at: new Date(Date.now() + INVITE_TTL_MS),
      })
      .returning()
    await recordEvent(ctx, eventFor(actor, 'invites.create', { type: 'invite', id: row!.id }, { email, role: input.role }), tx)
    return row!
  }).catch((error) => {
    if (isUniqueViolation(error, PENDING_INVITE_INDEX)) {
      throw new ConflictError('Another invite for this address was just created', 'conflict')
    }
    throw error
  })

  const link = new URL('/invite', ctx.base_url)
  link.searchParams.set('token', token)
  const mailed = ctx.mailer.delivers
  if (mailed) {
    const [inviter] = await ctx.db.select({ name: schema.users.name }).from(schema.users).where(eq(schema.users.id, actor.id))
    ctx.enqueue({
      name: 'mail.send',
      data: { to: email, ...inviteMail({ inviter: inviter?.name ?? 'Someone', email, link: link.toString(), role: input.role }) },
    })
  }
  return { invite, token, link: link.toString(), mailed }
}

export async function listInvites(
  ctx: Context,
  actor: Actor,
  input: { status?: InviteStatus | 'all' } & CursorInput,
) {
  authorize(invitePolicy, actor, 'read', undefined)
  const now = new Date()
  const filters: (SQL | undefined)[] = []
  if (input.status === 'pending') filters.push(isNull(schema.invites.accepted_at), gt(schema.invites.expires_at, now))
  if (input.status === 'accepted') filters.push(isNotNull(schema.invites.accepted_at))
  if (input.status === 'expired') filters.push(isNull(schema.invites.accepted_at), lte(schema.invites.expires_at, now))
  const page = keyset(
    [
      { expr: schema.invites.created_at, type: 'timestamptz', direction: 'desc' },
      { expr: schema.invites.id, type: 'uuid', direction: 'desc' },
    ],
    input,
  )
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, invite: schema.invites })
    .from(schema.invites)
    .where(and(...filters, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return { rows: result.rows.map((row) => row.invite), next_cursor: result.next_cursor }
}

/** Withdraw a pending invite. Needs a recent re-authentication. */
export async function revokeInvite(ctx: Context, actor: Actor, id: string) {
  authorize(invitePolicy, actor, 'revoke', undefined)
  assertStepUp(actor)
  const [invite] = await ctx.db
    .delete(schema.invites)
    .where(and(eq(schema.invites.id, id), isNull(schema.invites.accepted_at)))
    .returning()
  if (!invite) throw new NotFoundError('Invite not found')
  await recordEvent(ctx, eventFor(actor, 'invites.revoke', { type: 'invite', id }, { email: invite.email }))
}

/**
 * Accept an invite by its link token: creates the account with the invited role (or returns
 * the existing one) and marks the invite accepted. Having the token is as good as the email
 * link: it only reached the invited mailbox. The caller then starts a session for the user.
 */
/** What an invite link offers, shown before it is accepted. Holding the link is the only proof needed. */
export interface InvitePreview {
  email: string
  role: Role
  inviter_name: string | null
  expires_at: Date
}

/** Look up a pending invite by its link token, without accepting it. */
export async function previewInvite(ctx: Context, token: string): Promise<InvitePreview> {
  const [row] = await ctx.db
    .select({
      email: schema.invites.email,
      role: schema.invites.role,
      expires_at: schema.invites.expires_at,
      inviter_name: schema.users.name,
    })
    .from(schema.invites)
    .leftJoin(schema.users, eq(schema.users.id, schema.invites.invited_by_id))
    .where(and(eq(schema.invites.token_hash, sha256(token)), isNull(schema.invites.accepted_at), gt(schema.invites.expires_at, new Date())))
    .limit(1)
  if (!row) throw new NotFoundError('This invite is invalid or has expired', 'invalid_invite')
  return { email: row.email, role: row.role, inviter_name: row.inviter_name, expires_at: row.expires_at }
}

export async function acceptInvite(ctx: Context, token: string, input: { name?: string } = {}): Promise<User> {
  const [invite] = await ctx.db
    .select()
    .from(schema.invites)
    .where(and(eq(schema.invites.token_hash, sha256(token)), isNull(schema.invites.accepted_at), gt(schema.invites.expires_at, new Date())))
    .limit(1)
  if (!invite) throw new NotFoundError('This invite is invalid or has expired', 'invalid_invite')
  const user = await provisionUser(ctx, { email: invite.email, name: input.name }, { method: 'email' })
  // The account may have existed already, in which case provisioning left the invite alone.
  await ctx.db
    .update(schema.invites)
    .set({ accepted_at: new Date() })
    .where(and(eq(schema.invites.id, invite.id), isNull(schema.invites.accepted_at)))
  return user
}
