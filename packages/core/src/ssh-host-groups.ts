import { type Executor, schema } from '@certifly/db'
import { isValidDomainPattern, isValidSourceAddressList, matchesDomainPattern, SSH_USER_EXTENSIONS } from '@certifly/pki'
import { and, count, eq } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshHostGroupPolicy } from './policies'
import { checkSlug } from './ssh-cas'
import { hasControlCharacters } from './text'

export type SshHostGroupRow = typeof schema.sshHostGroups.$inferSelect
export type SshKeyPolicy = SshHostGroupRow['key_policy']

export const SSH_KEY_POLICIES = schema.sshKeyPolicy.enumValues

const HOUR = 3600
const DAY = 24 * HOUR
export const SSH_LIMITS = {
  /** User certificate lifetimes, in seconds. */
  user_ttl_min: 5 * 60,
  user_ttl_default: 8 * HOUR,
  user_ttl_max_default: 24 * HOUR,
  user_ttl_max_cap: 7 * DAY,
  host_ttl_min: HOUR,
  host_ttl_default: 90 * DAY,
  host_ttl_cap: 365 * DAY,
}
const DEFAULT_EXTENSIONS = ['permit-pty']
const MAX_PATTERNS = 100

const subjectOf = (id: string) => ({ type: 'ssh_host_group', id })

export interface SshHostGroupInput {
  name: string
  slug: string
  description?: string
  ssh_ca_id: string
  host_patterns?: string[]
  user_ttl_default_seconds?: number
  user_ttl_max_seconds?: number
  user_extensions?: string[]
  force_command?: string | null
  source_address?: string[]
  key_policy?: SshKeyPolicy
  host_ttl_seconds?: number
}

function seconds(value: number | undefined, fallback: number, min: number, max: number, field: string): number {
  const v = value ?? fallback
  if (!Number.isInteger(v) || v < min || v > max) throw new ValidationError(`${field} must be a whole number of seconds from ${min} to ${max}`, 'invalid_ttl')
  return v
}

function checkPatterns(list: readonly string[] | undefined): string[] {
  const patterns = [...new Set((list ?? []).map((p) => String(p).trim().toLowerCase()).filter(Boolean))]
  if (patterns.length > MAX_PATTERNS) throw new ValidationError(`At most ${MAX_PATTERNS} host patterns`, 'invalid_host_pattern')
  const bad = patterns.find((p) => !isValidDomainPattern(p))
  if (bad) throw new ValidationError(`Not a valid host name pattern: ${bad.slice(0, 80)}`, 'invalid_host_pattern')
  return patterns
}

/** Whether a host name falls under one of a host group's patterns. */
export function matchesHostPatterns(name: string, patterns: readonly string[]): boolean {
  const lower = name.toLowerCase()
  return patterns.some((p) => matchesDomainPattern(lower, p))
}

type Settings = Partial<Pick<typeof schema.sshHostGroups.$inferInsert, 'host_patterns' | 'user_ttl_default_seconds' | 'user_ttl_max_seconds' | 'user_extensions' | 'force_command' | 'source_address' | 'key_policy' | 'host_ttl_seconds'>>

function checkSettings(input: Partial<SshHostGroupInput>, current?: SshHostGroupRow): Settings {
  const out: Settings = {}
  if (input.host_patterns !== undefined) out.host_patterns = checkPatterns(input.host_patterns)
  const defaultTtl = input.user_ttl_default_seconds ?? current?.user_ttl_default_seconds
  const maxTtl = input.user_ttl_max_seconds ?? current?.user_ttl_max_seconds
  if (!current || input.user_ttl_default_seconds !== undefined || input.user_ttl_max_seconds !== undefined) {
    const max = seconds(maxTtl, SSH_LIMITS.user_ttl_max_default, SSH_LIMITS.user_ttl_min, SSH_LIMITS.user_ttl_max_cap, 'user_ttl_max_seconds')
    const def = seconds(defaultTtl, Math.min(SSH_LIMITS.user_ttl_default, max), SSH_LIMITS.user_ttl_min, SSH_LIMITS.user_ttl_max_cap, 'user_ttl_default_seconds')
    if (def > max) throw new ValidationError('The default lifetime cannot be longer than the maximum', 'invalid_ttl')
    out.user_ttl_default_seconds = def
    out.user_ttl_max_seconds = max
  }
  if (input.user_extensions !== undefined || !current) {
    const extensions = [...new Set(input.user_extensions ?? DEFAULT_EXTENSIONS)]
    const bad = extensions.find((e) => !(SSH_USER_EXTENSIONS as readonly string[]).includes(e))
    if (bad) throw new ValidationError(`Unknown extension: ${String(bad).slice(0, 64)}. Use ${SSH_USER_EXTENSIONS.join(', ')}`, 'invalid_extension')
    out.user_extensions = extensions.sort()
  }
  if (input.force_command !== undefined) {
    const command = input.force_command === null ? null : String(input.force_command).trim() || null
    if (command && (command.length > 1024 || /[\r\n\0]/.test(command))) throw new ValidationError('The forced command is invalid', 'invalid_force_command')
    out.force_command = command
  }
  if (input.source_address !== undefined) {
    const list = [...new Set(input.source_address.map((a) => String(a).trim()).filter(Boolean))]
    if (list.length && !isValidSourceAddressList(list)) throw new ValidationError('Source addresses must be IP addresses or CIDR ranges', 'invalid_source_address')
    out.source_address = list
  }
  if (input.key_policy !== undefined) {
    if (!SSH_KEY_POLICIES.includes(input.key_policy)) throw new ValidationError(`The key policy must be one of ${SSH_KEY_POLICIES.join(', ')}`, 'invalid_key_policy')
    out.key_policy = input.key_policy
  }
  if (input.host_ttl_seconds !== undefined || !current) {
    out.host_ttl_seconds = seconds(input.host_ttl_seconds, SSH_LIMITS.host_ttl_default, SSH_LIMITS.host_ttl_min, SSH_LIMITS.host_ttl_cap, 'host_ttl_seconds')
  }
  return out
}

/** The name goes into the ssh config the CLI writes, so it must stay on one line. */
function checkGroupName(value: unknown): string {
  const name = String(value ?? '').trim()
  if (!name || name.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  if (hasControlCharacters(name)) throw new ValidationError('The name may not contain line breaks or control characters')
  return name
}

function slugTaken(error: unknown): never {
  if (isUniqueViolation(error, 'ssh_host_groups_slug_unique')) throw new ConflictError('Another host group already uses this slug', 'slug_taken')
  throw error
}

export async function createSshHostGroup(ctx: Context, actor: Actor, input: SshHostGroupInput): Promise<SshHostGroupRow> {
  authorize(sshHostGroupPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  const slug = checkSlug(input.slug)
  const name = checkGroupName(input.name)
  const settings = checkSettings(input)
  try {
    return await withTransaction(ctx, async (tx) => {
      const [ca] = await tx.select({ id: schema.sshCas.id }).from(schema.sshCas).where(eq(schema.sshCas.id, input.ssh_ca_id))
      if (!ca) throw new NotFoundError('SSH certificate authority not found')
      const [row] = await tx
        .insert(schema.sshHostGroups)
        .values({ slug, name, description: String(input.description ?? '').trim().slice(0, 1000), ssh_ca_id: input.ssh_ca_id, ...(settings as Required<Settings>) })
        .returning()
      await recordEvent(ctx, eventFor(actor, 'ssh_host_groups.create', subjectOf(row!.id), { slug, ssh_ca_id: input.ssh_ca_id }), tx)
      return row!
    })
  } catch (error) {
    return slugTaken(error)
  }
}

/** The slug and the CA of a host group never change: principals and trust depend on them. */
export async function updateSshHostGroup(ctx: Context, actor: Actor, id: string, input: Partial<Omit<SshHostGroupInput, 'slug' | 'ssh_ca_id'>>): Promise<SshHostGroupRow> {
  authorize(sshHostGroupPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const [current] = await tx.select().from(schema.sshHostGroups).where(eq(schema.sshHostGroups.id, id)).for('update')
    if (!current) throw new NotFoundError('Host group not found')
    const set: Partial<typeof schema.sshHostGroups.$inferInsert> = checkSettings(input, current)
    if (input.name !== undefined) {
      set.name = checkGroupName(input.name)
    }
    if (input.description !== undefined) set.description = String(input.description).trim().slice(0, 1000)
    if (!Object.keys(set).length) return current
    const [row] = await tx.update(schema.sshHostGroups).set(set).where(eq(schema.sshHostGroups.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'ssh_host_groups.update', subjectOf(id), { fields: Object.keys(set) }), tx)
    return row!
  })
}

export async function deleteSshHostGroup(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(sshHostGroupPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx.select().from(schema.sshHostGroups).where(eq(schema.sshHostGroups.id, id)).for('update')
    if (!row) throw new NotFoundError('Host group not found')
    const [hosts] = await tx.select({ n: count() }).from(schema.sshHosts).where(eq(schema.sshHosts.host_group_id, id))
    if ((hosts?.n ?? 0) > 0) throw new ConflictError('This host group still has hosts', 'host_group_in_use')
    await tx.delete(schema.sshHostGroups).where(eq(schema.sshHostGroups.id, id))
    await recordEvent(ctx, eventFor(actor, 'ssh_host_groups.delete', subjectOf(id), { slug: row.slug }), tx)
  })
}

export async function loadSshHostGroup(db: Executor, id: string): Promise<SshHostGroupRow> {
  const [row] = await db.select().from(schema.sshHostGroups).where(eq(schema.sshHostGroups.id, id))
  if (!row) throw new NotFoundError('Host group not found')
  return row
}

export type SshHostGroupListRow = SshHostGroupRow & { ca: { id: string; slug: string; name: string }; host_count: number; rule_count: number }

async function withDetails(db: Executor, rows: SshHostGroupRow[]): Promise<SshHostGroupListRow[]> {
  if (!rows.length) return []
  const cas = await db.select({ id: schema.sshCas.id, slug: schema.sshCas.slug, name: schema.sshCas.name }).from(schema.sshCas)
  const hosts = await db.select({ id: schema.sshHosts.host_group_id, n: count() }).from(schema.sshHosts).groupBy(schema.sshHosts.host_group_id)
  const rules = await db.select({ id: schema.sshAccessRules.host_group_id, n: count() }).from(schema.sshAccessRules).groupBy(schema.sshAccessRules.host_group_id)
  return rows.map((row) => ({
    ...row,
    ca: cas.find((c) => c.id === row.ssh_ca_id)!,
    host_count: hosts.find((h) => h.id === row.id)?.n ?? 0,
    rule_count: rules.find((r) => r.id === row.id)?.n ?? 0,
  }))
}

export async function listSshHostGroups(ctx: Context, actor: Actor, input: CursorInput & { ssh_ca_id?: string }) {
  authorize(sshHostGroupPolicy, actor, 'read', undefined)
  const page = keyset(byName(schema.sshHostGroups.name, schema.sshHostGroups.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, group: schema.sshHostGroups })
    .from(schema.sshHostGroups)
    .where(input.ssh_ca_id ? and(eq(schema.sshHostGroups.ssh_ca_id, input.ssh_ca_id), page.where) : page.where)
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return { rows: await withDetails(ctx.db, result.rows.map((r) => r.group)), next_cursor: result.next_cursor }
}

export async function getSshHostGroup(ctx: Context, actor: Actor, id: string): Promise<SshHostGroupListRow> {
  authorize(sshHostGroupPolicy, actor, 'read', undefined)
  const [detail] = await withDetails(ctx.db, [await loadSshHostGroup(ctx.db, id)])
  return detail!
}
