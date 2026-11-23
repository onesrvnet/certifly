import { schema } from '@certifly/db'
import { and, asc, desc, eq, gt, gte, inArray, isNotNull, lt, lte, ne, sql } from 'drizzle-orm'
import { listEvents } from './audit'
import { certificateStats } from './certificates'
import type { Context } from './context'
import { type Actor, alertPolicy, auditPolicy, authorize, caPolicy, certificatePolicy } from './policies'
import { presentEvent } from './presenters'

const DAY_MS = 24 * 60 * 60 * 1000
const WEEK_MS = 7 * DAY_MS
/** Weeks shown in the expiry timeline (about 90 days) and in the issuance trend. */
export const EXPIRY_WEEKS = 13
export const ISSUED_WEEKS = 8
/** Certificates and CAs that run out within these windows need attention. */
const CERT_ATTENTION_DAYS = 30
const CA_ATTENTION_DAYS = 365
const ATTENTION_LIMIT = 8
const ACTIVITY_LIMIT = 8

export type AttentionItem =
  | { kind: 'certificate_expiring'; id: string; name: string; not_after: string }
  | { kind: 'ca_expiring'; id: string; name: string; not_after: string }
  | { kind: 'crl_late'; id: string; name: string; next_update: string }
  | { kind: 'delivery_failed'; id: string; name: string | null; event: string | null; at: string }

export type CrlState = 'ok' | 'late' | 'none'

export interface DashboardCa {
  id: string
  name: string
  parent_ca_id: string | null
  status: (typeof schema.caStatus.enumValues)[number]
  not_after: string | null
  active_certificates: number
  expiring_within_30_days: number
  crl_next_update: string | null
  crl_state: CrlState
}

/**
 * Everything the dashboard shows in one read: the certificate numbers, what needs attention now
 * (certificates and CAs running out, late CRLs, failed alert deliveries for those who may see
 * them), certificates expiring per week, certificates issued per week, and each CA's health.
 */
export async function dashboardOverview(ctx: Context, actor: Actor, now = new Date()) {
  authorize(certificatePolicy, actor, 'read', undefined)
  authorize(caPolicy, actor, 'read', undefined)
  const c = schema.certificates
  const ca = schema.certificateAuthorities
  const live = and(eq(c.status, 'active'), gt(c.not_after, now))!

  const stats = await certificateStats(ctx, actor, now)

  // Week i covers [now + i weeks, now + i+1 weeks).
  const expiryEnd = new Date(now.getTime() + EXPIRY_WEEKS * WEEK_MS)
  const expiryRows = await ctx.db
    .select({ week: sql<number>`floor(extract(epoch from (${c.not_after} - ${now.toISOString()}::timestamptz)) / ${WEEK_MS / 1000})`.mapWith(Number), n: sql<number>`count(*)`.mapWith(Number) })
    .from(c)
    .where(and(live, lt(c.not_after, expiryEnd)))
    .groupBy(sql`1`)
  const expiry_weeks = Array.from({ length: EXPIRY_WEEKS }, (_, i) => ({
    start: new Date(now.getTime() + i * WEEK_MS).toISOString(),
    count: expiryRows.find((r) => r.week === i)?.n ?? 0,
  }))

  // Week i (oldest first) ends ISSUED_WEEKS - 1 - i weeks before now.
  const issuedStart = new Date(now.getTime() - ISSUED_WEEKS * WEEK_MS)
  const issuedRows = await ctx.db
    .select({ week: sql<number>`floor(extract(epoch from (${now.toISOString()}::timestamptz - ${c.created_at})) / ${WEEK_MS / 1000})`.mapWith(Number), n: sql<number>`count(*)`.mapWith(Number) })
    .from(c)
    .where(and(ne(c.source, 'import'), gte(c.created_at, issuedStart)))
    .groupBy(sql`1`)
  const issued_per_week = Array.from({ length: ISSUED_WEEKS }, (_, i) => issuedRows.find((r) => r.week === ISSUED_WEEKS - 1 - i)?.n ?? 0)

  // CA health: active certificates, those expiring soon, and the CRL of the active key.
  const soon = and(live, lte(c.not_after, new Date(now.getTime() + CERT_ATTENTION_DAYS * DAY_MS)))!
  const counts = await ctx.db
    .select({ ca_id: c.ca_id, active: sql<number>`count(*) filter (where ${live})`.mapWith(Number), soon: sql<number>`count(*) filter (where ${soon})`.mapWith(Number) })
    .from(c)
    .where(isNotNull(c.ca_id))
    .groupBy(c.ca_id)
  const caRows = await ctx.db
    .select({ id: ca.id, name: ca.name, parent_ca_id: ca.parent_ca_id, status: ca.status, not_after: ca.not_after, crl_next_update: schema.crls.next_update })
    .from(ca)
    .leftJoin(schema.crls, and(eq(schema.crls.ca_id, ca.id), eq(schema.crls.key_id, ca.active_key_id)))
    .orderBy(asc(ca.created_at))
  const cas: DashboardCa[] = caRows.map((row) => {
    const count = counts.find((r) => r.ca_id === row.id)
    const signing = row.status === 'active'
    return {
      id: row.id,
      name: row.name,
      parent_ca_id: row.parent_ca_id,
      status: row.status,
      not_after: row.not_after?.toISOString() ?? null,
      active_certificates: count?.active ?? 0,
      expiring_within_30_days: count?.soon ?? 0,
      crl_next_update: row.crl_next_update?.toISOString() ?? null,
      crl_state: !signing || !row.crl_next_update ? 'none' : row.crl_next_update <= now ? 'late' : 'ok',
    }
  })

  const attention: AttentionItem[] = []
  for (const row of caRows) {
    if (row.status === 'active' && row.crl_next_update && row.crl_next_update <= now) attention.push({ kind: 'crl_late', id: row.id, name: row.name, next_update: row.crl_next_update.toISOString() })
  }
  if (alertPolicy.can(actor, 'read_deliveries', undefined)) {
    const d = schema.alertDeliveries
    const failed = await ctx.db
      .select({ id: d.id, name: schema.alertChannels.name, event: d.event, at: d.updated_at })
      .from(d)
      .leftJoin(schema.alertChannels, eq(schema.alertChannels.id, d.channel_id))
      .where(and(eq(d.status, 'failed'), eq(d.test, false), gt(d.updated_at, new Date(now.getTime() - 7 * DAY_MS))))
      .orderBy(desc(d.updated_at))
      .limit(3)
    for (const row of failed) attention.push({ kind: 'delivery_failed', id: row.id, name: row.name, event: row.event, at: row.at.toISOString() })
  }
  const caSoon = new Date(now.getTime() + CA_ATTENTION_DAYS * DAY_MS)
  for (const row of caRows) {
    if (row.status === 'active' && row.not_after && row.not_after > now && row.not_after <= caSoon) attention.push({ kind: 'ca_expiring', id: row.id, name: row.name, not_after: row.not_after.toISOString() })
  }
  const certs = await ctx.db
    .select({ id: c.id, common_name: c.common_name, sans: c.sans, not_after: c.not_after })
    .from(c)
    .where(soon)
    .orderBy(asc(c.not_after))
    .limit(ATTENTION_LIMIT)
  for (const row of certs) {
    attention.push({ kind: 'certificate_expiring', id: row.id, name: row.common_name ?? row.sans?.[0]?.value ?? row.id, not_after: row.not_after.toISOString() })
  }

  const activity = auditPolicy.can(actor, 'read', undefined) ? await latestActivity(ctx, actor) : []

  return { stats, expiry_weeks, issued_per_week, cas, attention: attention.slice(0, ATTENTION_LIMIT), activity }
}

/** The latest audit entries, each with the current name of what it was about, when that still exists. */
async function latestActivity(ctx: Context, actor: Actor) {
  const { rows } = await listEvents(ctx, actor, { limit: ACTIVITY_LIMIT })
  const ids = (type: string) => [...new Set(rows.filter((r) => r.event.subject_type === type && r.event.subject_id).map((r) => r.event.subject_id!))]
  const names = new Map<string, string>()
  const add = (list: { id: string; name: string | null }[]) => list.forEach((row) => row.name && names.set(row.id, row.name))
  const lookups: Promise<void>[] = []
  const certIds = ids('certificate')
  if (certIds.length) {
    const c = schema.certificates
    lookups.push(ctx.db.select({ id: c.id, common_name: c.common_name, sans: c.sans }).from(c).where(inArray(c.id, certIds)).then((list) => add(list.map((r) => ({ id: r.id, name: r.common_name ?? r.sans?.[0]?.value ?? null })))))
  }
  const named = [
    ['certificate_authority', schema.certificateAuthorities],
    ['template', schema.templates],
    ['tag', schema.tags],
    ['trust_bundle', schema.trustBundles],
    ['user', schema.users],
  ] as const
  for (const [type, table] of named) {
    const list = ids(type)
    if (list.length) lookups.push(ctx.db.select({ id: table.id, name: table.name }).from(table).where(inArray(table.id, list)).then(add))
  }
  await Promise.all(lookups)
  return rows.map((row) => ({ ...presentEvent(actor, row), subject_name: row.event.subject_id ? (names.get(row.event.subject_id) ?? null) : null }))
}
