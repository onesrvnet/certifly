import { type Executor, schema } from '@certifly/db'
import { and, eq, inArray } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshAccessPolicy } from './policies'
import { ensureUsername } from './usernames'

export type SshAccessRuleRow = typeof schema.sshAccessRules.$inferSelect

/** A local login name as an admin may write it into a rule. Mixed case is allowed: local accounts can have it. */
export const LOGIN_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/
const MAX_LOGINS = 50
const subjectOf = (id: string) => ({ type: 'ssh_access_rule', id })

export interface SshAccessRuleInput {
  host_group_id: string
  group_id: string
  logins?: string[]
  own_username?: boolean
}

function checkLogins(list: readonly string[] | undefined): string[] {
  const logins = [...new Set((list ?? []).map((l) => String(l).trim()).filter(Boolean))]
  if (logins.length > MAX_LOGINS) throw new ValidationError(`At most ${MAX_LOGINS} logins per rule`, 'invalid_login')
  const bad = logins.find((l) => !LOGIN_PATTERN.test(l))
  if (bad) throw new ValidationError(`Not a valid login name: ${bad.slice(0, 40)}`, 'invalid_login')
  return logins
}

function pairTaken(error: unknown): never {
  if (isUniqueViolation(error, 'ssh_access_rules_pair_idx')) throw new ConflictError('This group already has a rule for this host group', 'rule_exists')
  throw error
}

export async function createSshAccessRule(ctx: Context, actor: Actor, input: SshAccessRuleInput): Promise<SshAccessRuleRow> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  const logins = checkLogins(input.logins)
  const own_username = input.own_username === true
  if (!logins.length && !own_username) throw new ValidationError('A rule needs at least one login or the own username', 'rule_empty')
  try {
    return await withTransaction(ctx, async (tx) => {
      const [hg] = await tx.select({ id: schema.sshHostGroups.id }).from(schema.sshHostGroups).where(eq(schema.sshHostGroups.id, input.host_group_id))
      if (!hg) throw new NotFoundError('Host group not found')
      const [group] = await tx.select({ id: schema.groups.id }).from(schema.groups).where(eq(schema.groups.id, input.group_id))
      if (!group) throw new NotFoundError('Group not found')
      const [row] = await tx.insert(schema.sshAccessRules).values({ host_group_id: input.host_group_id, group_id: input.group_id, logins, own_username }).returning()
      await recordEvent(ctx, eventFor(actor, 'ssh_access_rules.create', subjectOf(row!.id), { host_group_id: input.host_group_id, group_id: input.group_id, logins, own_username }), tx)
      return row!
    })
  } catch (error) {
    return pairTaken(error)
  }
}

export async function updateSshAccessRule(ctx: Context, actor: Actor, id: string, input: { logins?: string[]; own_username?: boolean }): Promise<SshAccessRuleRow> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const [current] = await tx.select().from(schema.sshAccessRules).where(eq(schema.sshAccessRules.id, id)).for('update')
    if (!current) throw new NotFoundError('Access rule not found')
    const logins = input.logins !== undefined ? checkLogins(input.logins) : current.logins
    const own_username = input.own_username ?? current.own_username
    if (!logins.length && !own_username) throw new ValidationError('A rule needs at least one login or the own username', 'rule_empty')
    const [row] = await tx.update(schema.sshAccessRules).set({ logins, own_username }).where(eq(schema.sshAccessRules.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'ssh_access_rules.update', subjectOf(id), { logins, own_username }), tx)
    return row!
  })
}

export async function deleteSshAccessRule(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(sshAccessPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx.delete(schema.sshAccessRules).where(eq(schema.sshAccessRules.id, id)).returning()
    if (!row) throw new NotFoundError('Access rule not found')
    await recordEvent(ctx, eventFor(actor, 'ssh_access_rules.delete', subjectOf(id), { host_group_id: row.host_group_id, group_id: row.group_id }), tx)
  })
}

export type SshAccessRuleListRow = SshAccessRuleRow & { group: { id: string; name: string }; host_group: { id: string; slug: string; name: string } }

export async function listSshAccessRules(ctx: Context, actor: Actor, input: CursorInput & { host_group_id?: string; group_id?: string }) {
  authorize(sshAccessPolicy, actor, 'read', undefined)
  const page = keyset(byName(schema.groups.name, schema.sshAccessRules.id), input)
  const rows = await ctx.db
    .select({
      cursor_keys: page.keys,
      rule: schema.sshAccessRules,
      group: { id: schema.groups.id, name: schema.groups.name },
      host_group: { id: schema.sshHostGroups.id, slug: schema.sshHostGroups.slug, name: schema.sshHostGroups.name },
    })
    .from(schema.sshAccessRules)
    .innerJoin(schema.groups, eq(schema.groups.id, schema.sshAccessRules.group_id))
    .innerJoin(schema.sshHostGroups, eq(schema.sshHostGroups.id, schema.sshAccessRules.host_group_id))
    .where(and(input.host_group_id ? eq(schema.sshAccessRules.host_group_id, input.host_group_id) : undefined, input.group_id ? eq(schema.sshAccessRules.group_id, input.group_id) : undefined, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return { rows: result.rows.map((r): SshAccessRuleListRow => ({ ...r.rule, group: r.group, host_group: r.host_group })), next_cursor: result.next_cursor }
}

// ---------------------------------------------------------------------------------------------
// What a person may do

export interface HostGroupAccess {
  host_group: typeof schema.sshHostGroups.$inferSelect
  ca: typeof schema.sshCas.$inferSelect
  /** Local login names, the person's own username already filled in. Sorted, no repeats. */
  logins: string[]
  /**
   * What the certificate carries: `<slug>:<login>` for fixed logins and `<slug>:~<username>` for
   * the own username. The two never share a name, so a username can never equal a fixed login's
   * principal. Sorted, no repeats.
   */
  principals: string[]
}

/** The principal of a person's own username in a host group; hosts map it to the local account of that name. */
export const ownUsernamePrincipal = (slug: string, username: string) => `${slug}:~${username}`

/**
 * The host groups a person has at least one login in, through the groups they belong to. A
 * rule's own-username login is the person's SSH username (set on first use).
 */
export async function resolveSshAccess(db: Executor, user: { id: string; email: string; username: string | null }): Promise<{ username: string; access: HostGroupAccess[] }> {
  const rules = await db
    .select({ rule: schema.sshAccessRules, host_group: schema.sshHostGroups, ca: schema.sshCas })
    .from(schema.groupMembers)
    .innerJoin(schema.sshAccessRules, eq(schema.sshAccessRules.group_id, schema.groupMembers.group_id))
    .innerJoin(schema.sshHostGroups, eq(schema.sshHostGroups.id, schema.sshAccessRules.host_group_id))
    .innerJoin(schema.sshCas, eq(schema.sshCas.id, schema.sshHostGroups.ssh_ca_id))
    .where(eq(schema.groupMembers.user_id, user.id))
  const username = await ensureUsername(db, user)
  const by = new Map<string, HostGroupAccess>()
  for (const { rule, host_group, ca } of rules) {
    const entry = by.get(host_group.id) ?? { host_group, ca, logins: [], principals: [] }
    entry.logins.push(...rule.logins, ...(rule.own_username ? [username] : []))
    entry.principals.push(...rule.logins.map((login) => `${host_group.slug}:${login}`), ...(rule.own_username ? [ownUsernamePrincipal(host_group.slug, username)] : []))
    by.set(host_group.id, entry)
  }
  const access = [...by.values()]
    .map((e) => ({ ...e, logins: [...new Set(e.logins)].sort(), principals: [...new Set(e.principals)].sort() }))
    .filter((e) => e.logins.length > 0)
    .sort((a, b) => a.host_group.name.localeCompare(b.host_group.name))
  return { username, access }
}

/** The hosts a person can reach: hosts in their host groups, with the logins they hold there. */
export async function listReachableHosts(ctx: Context, user: { id: string; email: string; username: string | null }, input: CursorInput) {
  const { access } = await resolveSshAccess(ctx.db, user)
  const groupIds = access.map((a) => a.host_group.id)
  if (!groupIds.length) return { rows: [], next_cursor: null as string | null }
  const page = keyset(byName(schema.sshHosts.name, schema.sshHosts.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, host: schema.sshHosts })
    .from(schema.sshHosts)
    .where(and(inArray(schema.sshHosts.host_group_id, groupIds), page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return {
    rows: result.rows.map((r) => {
      const entry = access.find((a) => a.host_group.id === r.host.host_group_id)!
      return { host: r.host, host_group: entry.host_group, logins: entry.logins }
    }),
    next_cursor: result.next_cursor,
  }
}
