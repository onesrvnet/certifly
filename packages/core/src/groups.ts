import { type Executor, schema } from '@certifly/db'
import { and, count, eq, inArray, notInArray, sql } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshAccessPolicy } from './policies'

export type GroupRow = typeof schema.groups.$inferSelect

const MAX_PROVIDER_GROUPS = 50
const subjectOf = (id: string) => ({ type: 'group', id })

function checkName(name: string): string {
  const value = String(name ?? '').trim()
  if (!value || value.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  return value
}

function checkProviderGroups(list: readonly string[] | undefined): string[] {
  if (list === undefined) return []
  if (!Array.isArray(list) || list.length > MAX_PROVIDER_GROUPS) throw new ValidationError(`At most ${MAX_PROVIDER_GROUPS} provider groups`, 'invalid_provider_groups')
  const out = [...new Set(list.map((g) => String(g).trim()).filter(Boolean))]
  if (out.some((g) => g.length > 200)) throw new ValidationError('A provider group name may have at most 200 characters', 'invalid_provider_groups')
  return out
}

function nameTaken(error: unknown): never {
  if (isUniqueViolation(error, 'groups_name_lower_idx')) throw new ConflictError('Another group already has this name', 'group_name_taken')
  throw error
}

export interface GroupInput {
  name: string
  description?: string
  provider_groups?: string[]
}

export async function createGroup(ctx: Context, actor: Actor, input: GroupInput): Promise<GroupRow> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  const values = { name: checkName(input.name), description: String(input.description ?? '').trim().slice(0, 1000), provider_groups: checkProviderGroups(input.provider_groups) }
  try {
    return await withTransaction(ctx, async (tx) => {
      const [row] = await tx.insert(schema.groups).values(values).returning()
      await recordEvent(ctx, eventFor(actor, 'groups.create', subjectOf(row!.id), { name: values.name }), tx)
      return row!
    })
  } catch (error) {
    return nameTaken(error)
  }
}

export async function updateGroup(ctx: Context, actor: Actor, id: string, input: Partial<GroupInput>): Promise<GroupRow> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  const set: Partial<typeof schema.groups.$inferInsert> = {}
  if (input.name !== undefined) set.name = checkName(input.name)
  if (input.description !== undefined) set.description = String(input.description).trim().slice(0, 1000)
  if (input.provider_groups !== undefined) set.provider_groups = checkProviderGroups(input.provider_groups)
  try {
    return await withTransaction(ctx, async (tx) => {
      const [row] = Object.keys(set).length
        ? await tx.update(schema.groups).set(set).where(eq(schema.groups.id, id)).returning()
        : await tx.select().from(schema.groups).where(eq(schema.groups.id, id))
      if (!row) throw new NotFoundError('Group not found')
      if (Object.keys(set).length) await recordEvent(ctx, eventFor(actor, 'groups.update', subjectOf(id), { fields: Object.keys(set) }), tx)
      return row
    })
  } catch (error) {
    return nameTaken(error)
  }
}

/** Deleting a group also removes the access rules built on it. */
export async function deleteGroup(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx.delete(schema.groups).where(eq(schema.groups.id, id)).returning()
    if (!row) throw new NotFoundError('Group not found')
    await recordEvent(ctx, eventFor(actor, 'groups.delete', subjectOf(id), { name: row.name }), tx)
  })
}

async function memberCounts(db: Executor, ids: string[]): Promise<Map<string, number>> {
  if (!ids.length) return new Map()
  const rows = await db
    .select({ group_id: schema.groupMembers.group_id, n: count() })
    .from(schema.groupMembers)
    .where(inArray(schema.groupMembers.group_id, ids))
    .groupBy(schema.groupMembers.group_id)
  return new Map(rows.map((r) => [r.group_id, r.n]))
}

export async function listGroups(ctx: Context, actor: Actor, input: CursorInput) {
  authorize(sshAccessPolicy, actor, 'read', undefined)
  const page = keyset(byName(schema.groups.name, schema.groups.id), input)
  const rows = await ctx.db.select({ cursor_keys: page.keys, group: schema.groups }).from(schema.groups).where(page.where).orderBy(...page.orderBy).limit(page.limit)
  const result = paged(rows, input.limit)
  const counts = await memberCounts(ctx.db, result.rows.map((r) => r.group.id))
  return { rows: result.rows.map((r) => ({ ...r.group, member_count: counts.get(r.group.id) ?? 0 })), next_cursor: result.next_cursor }
}

export async function getGroup(ctx: Context, actor: Actor, id: string) {
  authorize(sshAccessPolicy, actor, 'read', undefined)
  const [group] = await ctx.db.select().from(schema.groups).where(eq(schema.groups.id, id))
  if (!group) throw new NotFoundError('Group not found')
  const counts = await memberCounts(ctx.db, [id])
  return { ...group, member_count: counts.get(id) ?? 0 }
}

export async function listGroupMembers(ctx: Context, actor: Actor, group_id: string, input: CursorInput) {
  authorize(sshAccessPolicy, actor, 'read', undefined)
  const page = keyset(byName(schema.users.name, schema.users.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, user: schema.users, source: schema.groupMembers.source, added_at: schema.groupMembers.created_at })
    .from(schema.groupMembers)
    .innerJoin(schema.users, eq(schema.users.id, schema.groupMembers.user_id))
    .where(and(eq(schema.groupMembers.group_id, group_id), page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  return paged(rows, input.limit)
}

/** Add a person to a group by hand. A provider-sourced membership becomes a manual one. */
export async function addGroupMember(ctx: Context, actor: Actor, group_id: string, user_id: string): Promise<void> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const [group] = await tx.select({ id: schema.groups.id }).from(schema.groups).where(eq(schema.groups.id, group_id))
    if (!group) throw new NotFoundError('Group not found')
    const [user] = await tx.select({ id: schema.users.id }).from(schema.users).where(eq(schema.users.id, user_id))
    if (!user) throw new NotFoundError('User not found')
    await tx
      .insert(schema.groupMembers)
      .values({ group_id, user_id, source: 'manual' })
      .onConflictDoUpdate({ target: [schema.groupMembers.group_id, schema.groupMembers.user_id], set: { source: 'manual' } })
    await recordEvent(ctx, eventFor(actor, 'group_members.create', subjectOf(group_id), { user_id }), tx)
  })
}

/** Remove a manually added member. Members that come from the identity provider leave with their provider group. */
export async function removeGroupMember(ctx: Context, actor: Actor, group_id: string, user_id: string): Promise<void> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx
      .select()
      .from(schema.groupMembers)
      .where(and(eq(schema.groupMembers.group_id, group_id), eq(schema.groupMembers.user_id, user_id)))
    if (!row) throw new NotFoundError('Membership not found')
    if (row.source === 'oidc') throw new ConflictError('This person is a member through the identity provider', 'member_from_provider')
    await tx.delete(schema.groupMembers).where(and(eq(schema.groupMembers.group_id, group_id), eq(schema.groupMembers.user_id, user_id)))
    await recordEvent(ctx, eventFor(actor, 'group_members.delete', subjectOf(group_id), { user_id }), tx)
  })
}

/**
 * Bring a person's provider-sourced memberships in line with the groups the identity provider
 * reported at sign-in: they join every group that lists one of their provider groups and leave
 * the provider-sourced ones that no longer match. Manual memberships stay as they are. Pass
 * `undefined` when the provider sent no groups claim at all, which changes nothing.
 */
export async function syncProviderGroups(ctx: Context, user: { id: string; role: 'admin' | 'operator' | 'viewer' }, provider_groups: readonly string[] | undefined): Promise<void> {
  if (provider_groups === undefined) return
  const reported = [...new Set(provider_groups.map((g) => String(g)))]
  await withTransaction(ctx, async (tx) => {
    const mapped = await tx.select({ id: schema.groups.id, provider_groups: schema.groups.provider_groups }).from(schema.groups).where(sql`cardinality(${schema.groups.provider_groups}) > 0`)
    const wanted = mapped.filter((g) => g.provider_groups.some((name) => reported.includes(name))).map((g) => g.id)
    let added = 0
    for (const group_id of wanted) {
      const rows = await tx.insert(schema.groupMembers).values({ group_id, user_id: user.id, source: 'oidc' }).onConflictDoNothing().returning({ group_id: schema.groupMembers.group_id })
      added += rows.length
    }
    const stale = await tx
      .delete(schema.groupMembers)
      .where(
        and(
          eq(schema.groupMembers.user_id, user.id),
          eq(schema.groupMembers.source, 'oidc'),
          wanted.length ? notInArray(schema.groupMembers.group_id, wanted) : undefined,
        ),
      )
      .returning({ group_id: schema.groupMembers.group_id })
    if (added || stale.length) {
      await recordEvent(ctx, eventFor({ id: user.id, role: user.role, kind: 'session', reauth_at: null }, 'group_members.sync', { type: 'user', id: user.id }, { added, removed: stale.length }), tx)
    }
  })
}
