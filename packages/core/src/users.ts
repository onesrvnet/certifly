import { schema, type Transaction } from '@certifly/db'
import { and, count, eq, ilike, isNull, ne, or, sql } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp, revokeUserSessions } from './auth/sessions'
import type { Context } from './context'
import { type CursorInput, byName, keyset, paged } from './cursor'
import { ConflictError, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, peoplePolicy, type Role, userPolicy } from './policies'
import { revokeUserSshCertificates } from './ssh-certificates'
import { setUsername } from './usernames'

export type UserRow = typeof schema.users.$inferSelect

/** Arbitrary constant that serialises changes to admins, so two admins cannot remove each other at once. */
const ADMIN_LOCK_ID = 727_004

/** Throws unless some other active admin remains once the one being changed is gone. */
export function assertAnotherAdmin(otherActiveAdmins: number): void {
  if (otherActiveAdmins < 1) throw new ConflictError('There must be at least one admin', 'last_admin')
}

async function loadUser(ctx: Context, actor: Actor, id: string, includeDeactivated = false): Promise<UserRow> {
  const [user] = await ctx.db
    .select()
    .from(schema.users)
    .where(and(eq(schema.users.id, id), includeDeactivated ? undefined : isNull(schema.users.deleted_at)))
    .limit(1)
  if (!user || !userPolicy.can(actor, 'read', user)) throw new NotFoundError('User not found')
  return user
}

export async function getUser(ctx: Context, actor: Actor, id: string) {
  return loadUser(ctx, actor, id, true)
}

/**
 * Users by name, for admins. Operators see every active person (the presenter leaves out
 * all but their names, email and username). Anyone else sees only themselves. Deactivated
 * users are left out unless an admin asks for them.
 */
export async function listUsers(
  ctx: Context,
  actor: Actor,
  input: { query?: string; role?: Role; include_deactivated?: boolean } & CursorInput,
) {
  const filters = []
  const isDirectory = !peoplePolicy.can(actor, 'list', undefined) && peoplePolicy.can(actor, 'search', undefined)
  if (!peoplePolicy.can(actor, 'list', undefined) && !isDirectory) filters.push(eq(schema.users.id, actor.id))
  if (!input.include_deactivated || isDirectory) filters.push(isNull(schema.users.deleted_at))
  if (input.role && !isDirectory) filters.push(eq(schema.users.role, input.role))
  if (input.query?.trim()) {
    const pattern = `%${input.query.trim().replace(/[\\%_]/g, '\\$&')}%`
    filters.push(or(ilike(schema.users.name, pattern), ilike(schema.users.email, pattern)))
  }
  const page = keyset(byName(schema.users.name, schema.users.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, user: schema.users })
    .from(schema.users)
    .where(and(...filters, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return { rows: result.rows.map((row) => row.user), next_cursor: result.next_cursor }
}

/** Change a user's own name or preferences (admins may change anyone's). */
export async function updateUser(ctx: Context, actor: Actor, id: string, input: { name?: string; preferences?: Record<string, unknown>; username?: string }) {
  const user = await loadUser(ctx, actor, id)
  authorize(userPolicy, actor, 'update', user)
  const set: Partial<typeof schema.users.$inferInsert> = {}
  if (input.name !== undefined) {
    const name = input.name.trim()
    if (!name) throw new ValidationError('Name cannot be empty')
    set.name = name
  }
  if (input.preferences) set.preferences = input.preferences
  if (input.username !== undefined) authorize(userPolicy, actor, 'set_username', user)
  if (Object.keys(set).length === 0 && input.username === undefined) return user
  return withTransaction(ctx, async (tx) => {
    let updated = user
    if (Object.keys(set).length) updated = (await tx.update(schema.users).set(set).where(eq(schema.users.id, user.id)).returning())[0]!
    if (input.username !== undefined) {
      updated = { ...updated, username: await setUsername(tx, user.id, input.username) }
      set.username = updated.username
    }
    await recordEvent(ctx, eventFor(actor, 'users.update', { type: 'user', id: user.id }, { fields: Object.keys(set) }), tx)
    return updated
  })
}

/**
 * Take the admin lock, then read the user again and lock their row. Decisions about the last
 * admin rest on this fresh row: the one read before the lock may be out of date by now.
 */
async function lockAdmins(tx: Transaction, id: string) {
  await tx.execute(sql`select pg_advisory_xact_lock(${ADMIN_LOCK_ID})`)
  const [user] = await tx
    .select()
    .from(schema.users)
    .where(and(eq(schema.users.id, id), isNull(schema.users.deleted_at)))
    .for('update')
  if (!user) throw new NotFoundError('User not found')
  return user
}

/** Throws when `user` is an active admin and no other active admin exists. Call with the admin lock held. */
async function assertNotLastAdmin(tx: Transaction, user: UserRow) {
  if (user.role !== 'admin' || user.deleted_at) return
  const [row] = await tx
    .select({ n: count() })
    .from(schema.users)
    .where(and(eq(schema.users.role, 'admin'), isNull(schema.users.deleted_at), ne(schema.users.id, user.id)))
  assertAnotherAdmin(row?.n ?? 0)
}

/** Change a user's role. The last admin cannot be demoted. Needs a recent re-authentication. */
export async function updateUserRole(ctx: Context, actor: Actor, id: string, role: Role) {
  const user = await loadUser(ctx, actor, id)
  authorize(userPolicy, actor, 'change_role', user)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const fresh = await lockAdmins(tx, user.id)
    if (fresh.role === role) return fresh
    if (role !== 'admin') await assertNotLastAdmin(tx, fresh)
    const [updated] = await tx.update(schema.users).set({ role }).where(eq(schema.users.id, fresh.id)).returning()
    await recordEvent(ctx, eventFor(actor, 'users.update_role', { type: 'user', id: fresh.id }, { from: fresh.role, to: role }), tx)
    return updated!
  })
}

/**
 * Deactivate a user: they can no longer sign in and their sessions end. Their API keys and
 * the invites they sent but nobody accepted yet are deleted, so reactivating them later does
 * not bring old credentials back. The row stays so the audit log keeps a name. The last admin
 * cannot be deactivated. Needs a recent re-authentication.
 */
export async function deactivateUser(ctx: Context, actor: Actor, id: string) {
  const user = await loadUser(ctx, actor, id)
  authorize(userPolicy, actor, 'deactivate', user)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const fresh = await lockAdmins(tx, user.id)
    await assertNotLastAdmin(tx, fresh)
    const [row] = await tx.update(schema.users).set({ deleted_at: new Date() }).where(eq(schema.users.id, fresh.id)).returning()
    const keys = await tx.delete(schema.apiKeys).where(eq(schema.apiKeys.user_id, fresh.id)).returning({ id: schema.apiKeys.id })
    const invites = await tx
      .delete(schema.invites)
      .where(and(eq(schema.invites.invited_by_id, fresh.id), isNull(schema.invites.accepted_at)))
      .returning({ id: schema.invites.id })
    await revokeUserSessions(ctx, actor, fresh, tx)
    await tx.update(schema.cliSessions).set({ revoked_at: new Date() }).where(and(eq(schema.cliSessions.user_id, fresh.id), isNull(schema.cliSessions.revoked_at)))
    const ssh_certificates_revoked = await revokeUserSshCertificates(ctx, tx, actor, fresh.id)
    await recordEvent(
      ctx,
      eventFor(actor, 'users.deactivate', { type: 'user', id: fresh.id }, { api_keys_deleted: keys.length, invites_deleted: invites.length, ssh_certificates_revoked }),
      tx,
    )
    return row!
  })
}

/** Let a deactivated user sign in again. Needs a recent re-authentication. */
export async function reactivateUser(ctx: Context, actor: Actor, id: string) {
  const user = await loadUser(ctx, actor, id, true)
  authorize(userPolicy, actor, 'reactivate', user)
  assertStepUp(actor)
  if (!user.deleted_at) return user
  const [updated] = await ctx.db.update(schema.users).set({ deleted_at: null }).where(eq(schema.users.id, user.id)).returning()
  await recordEvent(ctx, eventFor(actor, 'users.reactivate', { type: 'user', id: user.id }))
  return updated!
}
