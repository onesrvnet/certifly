import { createHmac } from 'node:crypto'
import { type AlertChannelConfig, type AlertRuleFilter, type Executor, schema } from '@certifly/db'
import { and, eq, gt, inArray, isNull, lte, ne, notExists, type SQL, sql } from 'drizzle-orm'
import { alias } from 'drizzle-orm/pg-core'
import { type EventRow, eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { decryptSecret, encryptSecret, randomToken } from './crypto'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { NotFoundError, ValidationError } from './errors'
import { renderMail } from './mail-templates'
import { type Actor, alertPolicy, authorize } from './policies'

export type AlertChannelRow = typeof schema.alertChannels.$inferSelect
export type AlertRuleRow = typeof schema.alertRules.$inferSelect
export type AlertDeliveryRow = typeof schema.alertDeliveries.$inferSelect
export type AlertEvent = (typeof schema.alertEvent.enumValues)[number]
export type AlertChannelKind = AlertChannelRow['kind']

export const ALERT_EVENTS = schema.alertEvent.enumValues
/** Events about a certificate or CA running out; they take warning thresholds in days. */
const EXPIRY_EVENTS: readonly AlertEvent[] = ['expiring', 'ca_expiring', 'ssh_host_expiring']
/** Events about leaf certificates, which template filters apply to. */
const CERTIFICATE_EVENTS: readonly AlertEvent[] = ['expiring', 'issued', 'revoked']

/** pg-boss retries a failed delivery this often, with growing delays. */
export const ALERT_DELIVERY_RETRIES = 6
export const ALERT_MAX_ATTEMPTS = ALERT_DELIVERY_RETRIES + 1
export const WEBHOOK_TIMEOUT_MS = 10_000
/** Only the start of a receiver's answer is read, for the error message. */
const WEBHOOK_RESPONSE_LIMIT = 4096
const MAX_ERROR_LENGTH = 500
const MAX_RECIPIENTS = 20
const MAX_CHANNELS_PER_RULE = 10
const MAX_FILTER_IDS = 100
const MAX_THRESHOLDS = 10
const DAY_MS = 24 * 60 * 60 * 1000
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const channelSubject = (id: string) => ({ type: 'alert_channel', id })
const ruleSubject = (id: string) => ({ type: 'alert_rule', id })

// ---------------------------------------------------------------------------------------------
// Webhook signatures

/** Header names of a webhook delivery. */
export const WEBHOOK_HEADERS = {
  signature: 'x-certifly-signature',
  timestamp: 'x-certifly-timestamp',
  event: 'x-certifly-event',
  delivery: 'x-certifly-delivery',
} as const

/**
 * The `X-Certifly-Signature` value: `sha256=` and the hex HMAC-SHA256 of the raw request body,
 * keyed with the channel's secret as UTF-8 text. The body carries the same `timestamp` as the
 * `X-Certifly-Timestamp` header, so the signature covers it: a receiver checks the signature
 * (in constant time), then that the timestamp is recent, which stops replays of an old body.
 */
export function webhookSignature(secret: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body, 'utf8').digest('hex')}`
}

// ---------------------------------------------------------------------------------------------
// Channels

export type CreateAlertChannelInput = { name: string; kind: 'email'; recipients: string[] } | { name: string; kind: 'webhook'; url: string }

export interface UpdateAlertChannelInput {
  name?: string
  recipients?: string[]
  url?: string
  /** Replace the webhook secret; the new one is returned once. */
  rotate_secret?: boolean
}

/** A channel and, right after it was created or rotated, its webhook secret: shown once, never again. */
export interface AlertChannelResult {
  channel: AlertChannelRow
  secret?: string
}

function checkName(name: string): string {
  const trimmed = name.trim()
  if (!trimmed || trimmed.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  return trimmed
}

function checkRecipients(recipients: string[]): string[] {
  const list = [...new Set(recipients.map((r) => r.trim().toLowerCase()).filter(Boolean))]
  if (!list.length) throw new ValidationError('Add at least one recipient', 'recipients_required')
  if (list.length > MAX_RECIPIENTS) throw new ValidationError(`At most ${MAX_RECIPIENTS} recipients`)
  const bad = list.find((r) => r.length > 254 || !EMAIL.test(r))
  if (bad) throw new ValidationError(`Not an email address: ${bad}`, 'invalid_email')
  return list
}

/**
 * Webhooks must use http or https. Nothing else is checked: alerts to internal services are what
 * a self-hosted PKI is for. Redirects are never followed, and answers are cut short.
 */
function checkUrl(url: string): string {
  let parsed: URL
  try {
    parsed = new URL(url.trim())
  } catch {
    throw new ValidationError('The webhook URL is not valid', 'invalid_url')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new ValidationError('The webhook URL must use http or https', 'invalid_url')
  if (url.length > 2048) throw new ValidationError('The webhook URL may be at most 2048 characters', 'invalid_url')
  return parsed.toString()
}

const newSecret = () => `whsec_${randomToken(32)}`

async function findChannel(db: Executor, id: string): Promise<AlertChannelRow> {
  const [row] = await db.select().from(schema.alertChannels).where(eq(schema.alertChannels.id, id))
  if (!row) throw new NotFoundError('Alert channel not found')
  return row
}

/**
 * Create an alert channel: email recipients, or a webhook URL. A webhook gets a new secret,
 * returned only in this answer and stored encrypted; certifly signs every delivery with it.
 * Admins only, from a recently re-authenticated session.
 */
export async function createAlertChannel(ctx: Context, actor: Actor, input: CreateAlertChannelInput): Promise<AlertChannelResult> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  const name = checkName(input.name)
  let config: AlertChannelConfig
  let secret: string | undefined
  if (input.kind === 'email') config = { recipients: checkRecipients(input.recipients) }
  else if (input.kind === 'webhook') {
    secret = newSecret()
    config = { url: checkUrl(input.url), secret_enc: encryptSecret(ctx.secret_key, secret) }
  } else throw new ValidationError('The kind must be email or webhook')
  const channel = await withTransaction(ctx, async (tx) => {
    const [row] = await tx.insert(schema.alertChannels).values({ name, kind: input.kind, config }).returning()
    await recordEvent(ctx, eventFor(actor, 'alert_channels.create', channelSubject(row!.id), { kind: row!.kind }), tx)
    return row!
  })
  return { channel, ...(secret ? { secret } : {}) }
}

/** Change a channel's name, recipients or URL, or give a webhook a new secret (returned once). Admins, step-up. */
export async function updateAlertChannel(ctx: Context, actor: Actor, id: string, input: UpdateAlertChannelInput): Promise<AlertChannelResult> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  let secret: string | undefined
  const channel = await withTransaction(ctx, async (tx) => {
    const current = await findChannel(tx, id)
    let config = current.config
    if ('recipients' in config) {
      if (input.url !== undefined || input.rotate_secret) throw new ValidationError('An email channel has no URL or secret')
      if (input.recipients !== undefined) config = { recipients: checkRecipients(input.recipients) }
    } else {
      if (input.recipients !== undefined) throw new ValidationError('A webhook channel has no recipients')
      if (input.url !== undefined) config = { ...config, url: checkUrl(input.url) }
      if (input.rotate_secret) {
        secret = newSecret()
        config = { ...config, secret_enc: encryptSecret(ctx.secret_key, secret) }
      }
    }
    const [row] = await tx
      .update(schema.alertChannels)
      .set({ ...(input.name !== undefined ? { name: checkName(input.name) } : {}), config })
      .where(eq(schema.alertChannels.id, id))
      .returning()
    const changed = (['name', 'recipients', 'url'] as const).filter((key) => input[key] !== undefined)
    await recordEvent(ctx, eventFor(actor, 'alert_channels.update', channelSubject(id), { changed, secret_rotated: !!secret }), tx)
    return row!
  })
  return { channel, ...(secret ? { secret } : {}) }
}

/** Delete a channel and take it out of every rule; its delivery history stays. Admins, step-up. */
export async function deleteAlertChannel(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const channel = await findChannel(tx, id)
    await tx
      .update(schema.alertRules)
      .set({ channel_ids: sql`array_remove(${schema.alertRules.channel_ids}, ${id}::uuid)` })
      .where(sql`${id}::uuid = any(${schema.alertRules.channel_ids})`)
    await tx.delete(schema.alertChannels).where(eq(schema.alertChannels.id, id))
    await recordEvent(ctx, eventFor(actor, 'alert_channels.delete', channelSubject(id), { kind: channel.kind }), tx)
  })
}

/** Alert channels, alphabetically. Admins only: they hold recipients and webhook URLs. */
export async function listAlertChannels(ctx: Context, actor: Actor, input: CursorInput) {
  authorize(alertPolicy, actor, 'read', undefined)
  const ch = schema.alertChannels
  const page = keyset(byName(ch.name, ch.id), input)
  const rows = await ctx.db.select({ cursor_keys: page.keys, channel: ch }).from(ch).where(page.where).orderBy(...page.orderBy).limit(page.limit)
  return paged(rows, input.limit)
}

/**
 * Send a test alert through a channel right now and report how it went. It is stored with the
 * other deliveries (marked as a test) but never retried. Admins, step-up.
 */
export async function sendAlertTest(ctx: Context, actor: Actor, channel_id: string): Promise<AlertDeliveryRow> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  const channel = await findChannel(ctx.db, channel_id)
  const delivery = await withTransaction(ctx, async (tx) => {
    const [row] = await tx
      .insert(schema.alertDeliveries)
      .values({
        channel_id,
        event: null,
        test: true,
        dedupe_key: `test:${channel_id}:${crypto.randomUUID()}`,
        payload: { message: 'This is a test alert from certifly.', channel: { id: channel.id, name: channel.name } },
      })
      .returning()
    await recordEvent(ctx, eventFor(actor, 'alert_channels.test', channelSubject(channel_id), { delivery_id: row!.id, kind: channel.kind }), tx)
    return row!
  })
  return deliverAlert(ctx, delivery.id, { retry: false }).then((row) => row ?? delivery)
}

// ---------------------------------------------------------------------------------------------
// Rules

export interface AlertRuleInput {
  name: string
  event: AlertEvent
  ca_ids?: string[]
  template_ids?: string[]
  include_imported?: boolean
  days_before?: number[]
  channel_ids: string[]
  enabled?: boolean
}

function checkIds(ids: string[] | undefined, what: string): string[] {
  const list = [...new Set(ids ?? [])]
  if (list.length > MAX_FILTER_IDS) throw new ValidationError(`At most ${MAX_FILTER_IDS} ${what}`)
  return list
}

async function checkExisting(db: Executor, table: typeof schema.certificateAuthorities | typeof schema.templates | typeof schema.alertChannels, ids: string[], code: string) {
  if (!ids.length) return
  const rows = await db.select({ id: table.id }).from(table).where(inArray(table.id, ids))
  if (rows.length !== ids.length) throw new NotFoundError('Something the rule names does not exist', code)
}

/** A rule's settings, checked and normalised; filters that do not apply to the event are cleared. */
async function checkRule(db: Executor, input: AlertRuleInput) {
  const name = checkName(input.name)
  if (!ALERT_EVENTS.includes(input.event)) throw new ValidationError(`The event must be one of ${ALERT_EVENTS.join(', ')}`)
  const expiry = EXPIRY_EVENTS.includes(input.event)
  const certificates = CERTIFICATE_EVENTS.includes(input.event)
  const days = [...new Set(input.days_before ?? [])].sort((a, b) => b - a)
  if (expiry) {
    if (!days.length) throw new ValidationError('Give at least one warning threshold in days', 'thresholds_required')
    if (days.length > MAX_THRESHOLDS || days.some((d) => !Number.isInteger(d) || d < 1 || d > 3650)) {
      throw new ValidationError(`Up to ${MAX_THRESHOLDS} thresholds, each a whole number of days from 1 to 3650`, 'invalid_thresholds')
    }
  }
  const filter: AlertRuleFilter = {
    // SSH host warnings take no filters; the CA list names X.509 CAs.
    ca_ids: input.event === 'ssh_host_expiring' ? [] : checkIds(input.ca_ids, 'CAs'),
    template_ids: certificates ? checkIds(input.template_ids, 'templates') : [],
    // Only expiry warnings concern imported certificates: certifly neither issues nor revokes them.
    include_imported: input.event === 'expiring' ? (input.include_imported ?? false) : false,
  }
  const channel_ids = [...new Set(input.channel_ids)]
  if (!channel_ids.length) throw new ValidationError('Pick at least one channel', 'channels_required')
  if (channel_ids.length > MAX_CHANNELS_PER_RULE) throw new ValidationError(`At most ${MAX_CHANNELS_PER_RULE} channels per rule`)
  await checkExisting(db, schema.certificateAuthorities, filter.ca_ids, 'ca_not_found')
  await checkExisting(db, schema.templates, filter.template_ids, 'template_not_found')
  await checkExisting(db, schema.alertChannels, channel_ids, 'channel_not_found')
  return { name, event: input.event, filter, days_before: expiry ? days : [], channel_ids, enabled: input.enabled ?? true }
}

async function findRule(db: Executor, id: string): Promise<AlertRuleRow> {
  const [row] = await db.select().from(schema.alertRules).where(eq(schema.alertRules.id, id))
  if (!row) throw new NotFoundError('Alert rule not found')
  return row
}

/** Create an alert rule. Admins only, from a recently re-authenticated session. */
export async function createAlertRule(ctx: Context, actor: Actor, input: AlertRuleInput): Promise<AlertRuleRow> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const values = await checkRule(tx, input)
    const [row] = await tx.insert(schema.alertRules).values(values).returning()
    await recordEvent(ctx, eventFor(actor, 'alert_rules.create', ruleSubject(row!.id), { event: row!.event, channel_ids: row!.channel_ids, enabled: row!.enabled }), tx)
    return row!
  })
}

/** Change an alert rule; what is left out stays as it is. Admins, step-up. */
export async function updateAlertRule(ctx: Context, actor: Actor, id: string, input: Partial<AlertRuleInput>): Promise<AlertRuleRow> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const current = await findRule(tx, id)
    const values = await checkRule(tx, {
      name: input.name ?? current.name,
      event: input.event ?? current.event,
      ca_ids: input.ca_ids ?? current.filter.ca_ids,
      template_ids: input.template_ids ?? current.filter.template_ids,
      include_imported: input.include_imported ?? current.filter.include_imported,
      days_before: input.days_before ?? current.days_before,
      channel_ids: input.channel_ids ?? current.channel_ids,
      enabled: input.enabled ?? current.enabled,
    })
    const [row] = await tx.update(schema.alertRules).set(values).where(eq(schema.alertRules.id, id)).returning()
    const changed = Object.keys(input).filter((key) => input[key as keyof AlertRuleInput] !== undefined)
    await recordEvent(ctx, eventFor(actor, 'alert_rules.update', ruleSubject(id), { changed, enabled: row!.enabled }), tx)
    return row!
  })
}

/** Delete an alert rule; its delivery history stays. Admins, step-up. */
export async function deleteAlertRule(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(alertPolicy, actor, 'manage', undefined)
  assertStepUp(actor)
  await withTransaction(ctx, async (tx) => {
    const rule = await findRule(tx, id)
    await tx.delete(schema.alertRules).where(eq(schema.alertRules.id, id))
    await recordEvent(ctx, eventFor(actor, 'alert_rules.delete', ruleSubject(id), { event: rule.event }), tx)
  })
}

/** Alert rules, alphabetically. Admins only. */
export async function listAlertRules(ctx: Context, actor: Actor, input: CursorInput) {
  authorize(alertPolicy, actor, 'read', undefined)
  const r = schema.alertRules
  const page = keyset(byName(r.name, r.id), input)
  const rows = await ctx.db.select({ cursor_keys: page.keys, rule: r }).from(r).where(page.where).orderBy(...page.orderBy).limit(page.limit)
  return paged(rows, input.limit)
}

// ---------------------------------------------------------------------------------------------
// Deliveries

export interface ListAlertDeliveriesInput extends CursorInput {
  status?: AlertDeliveryRow['status']
  rule_id?: string
  channel_id?: string
}

export interface AlertDeliveryListRow {
  delivery: AlertDeliveryRow
  rule: { id: string; name: string } | null
  channel: { id: string; name: string; kind: AlertChannelKind } | null
}

/** Alert deliveries, newest first, with their rule and channel names. Operators and admins. */
export async function listAlertDeliveries(ctx: Context, actor: Actor, input: ListAlertDeliveriesInput) {
  authorize(alertPolicy, actor, 'read_deliveries', undefined)
  const d = schema.alertDeliveries
  const filters: (SQL | undefined)[] = []
  if (input.status) filters.push(eq(d.status, input.status))
  if (input.rule_id) filters.push(eq(d.rule_id, input.rule_id))
  if (input.channel_id) filters.push(eq(d.channel_id, input.channel_id))
  const page = keyset(
    [
      { expr: d.created_at, type: 'timestamptz', direction: 'desc' },
      { expr: d.id, type: 'uuid', direction: 'desc' },
    ],
    input,
  )
  const rows = await ctx.db
    .select({
      cursor_keys: page.keys,
      delivery: d,
      rule: { id: schema.alertRules.id, name: schema.alertRules.name },
      channel: { id: schema.alertChannels.id, name: schema.alertChannels.name, kind: schema.alertChannels.kind },
    })
    .from(d)
    .leftJoin(schema.alertRules, eq(schema.alertRules.id, d.rule_id))
    .leftJoin(schema.alertChannels, eq(schema.alertChannels.id, d.channel_id))
    .where(and(...filters, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  return paged(rows, input.limit) as { rows: AlertDeliveryListRow[]; next_cursor: string | null }
}

// ---------------------------------------------------------------------------------------------
// What an alert says

export interface CertificateFacts {
  id: string
  common_name: string | null
  sans: { type: string; value: string }[]
  serial: string
  not_after: string
  issuer_dn: string
  source: string
  ca: { id: string; name: string; slug: string } | null
  template: { id: string; name: string } | null
  url: string
}

export interface CaFacts {
  id: string
  name: string
  slug: string
  not_after: string | null
  url: string
}

const certificateFields = {
  id: schema.certificates.id,
  common_name: schema.certificates.common_name,
  sans: schema.certificates.sans,
  serial: schema.certificates.serial,
  not_after: schema.certificates.not_after,
  issuer_dn: schema.certificates.issuer_dn,
  source: schema.certificates.source,
  ca_id: schema.certificates.ca_id,
  template_id: schema.certificates.template_id,
  revocation_reason: schema.certificates.revocation_reason,
  revoked_at: schema.certificates.revoked_at,
  ca_name: schema.certificateAuthorities.name,
  ca_slug: schema.certificateAuthorities.slug,
  template_name: schema.templates.name,
}

/** Certificates with their CA and template names, for alert payloads. */
function loadCertificates(db: Executor, where: SQL | undefined) {
  return db
    .select(certificateFields)
    .from(schema.certificates)
    .leftJoin(schema.certificateAuthorities, eq(schema.certificateAuthorities.id, schema.certificates.ca_id))
    .leftJoin(schema.templates, eq(schema.templates.id, schema.certificates.template_id))
    .where(where)
}

type CertificateFactRow = Awaited<ReturnType<typeof loadCertificates>>[number]

function certificateFacts(ctx: Context, row: CertificateFactRow): CertificateFacts {
  return {
    id: row.id,
    common_name: row.common_name,
    sans: row.sans ?? [],
    serial: row.serial,
    not_after: row.not_after.toISOString(),
    issuer_dn: row.issuer_dn,
    source: row.source,
    ca: row.ca_id && row.ca_name && row.ca_slug ? { id: row.ca_id, name: row.ca_name, slug: row.ca_slug } : null,
    template: row.template_id && row.template_name ? { id: row.template_id, name: row.template_name } : null,
    url: `${ctx.base_url}/certificates/${row.id}`,
  }
}

/** What an SSH host certificate alert says about the host. */
export interface SshHostFacts {
  id: string | null
  name: string
  hostnames: string[]
  serial: string
  not_after: string
  url: string | null
}

function caFacts(ctx: Context, ca: { id: string; name: string; slug: string; not_after: Date | null }): CaFacts {
  return { id: ca.id, name: ca.name, slug: ca.slug, not_after: ca.not_after?.toISOString() ?? null, url: `${ctx.base_url}/certificate-authorities/${ca.id}` }
}

const certificateName = (cert: CertificateFacts) => cert.common_name ?? cert.sans[0]?.value ?? cert.serial

function inDays(days: number) {
  return days <= 0 ? 'today' : days === 1 ? 'in 1 day' : `in ${days} days`
}

/** The subject and text of an alert mail; webhooks get the payload as JSON instead. */
export function describeAlert(delivery: Pick<AlertDeliveryRow, 'event' | 'test' | 'payload'>): { subject: string; lines: string[]; url?: string } {
  const p = delivery.payload as {
    certificate?: CertificateFacts
    certificate_authority?: CaFacts
    ssh_host?: SshHostFacts
    days_left?: number
    reason?: string
    error?: string
  }
  if (delivery.test) return { subject: 'Test alert', lines: ['This is a test alert from certifly. The channel works.'] }
  const cert = p.certificate
  const ca = p.certificate_authority
  const certLines = (c: CertificateFacts) => [
    `Certificate: ${certificateName(c)}`,
    `Serial: ${c.serial}`,
    `Issuer: ${c.issuer_dn}`,
    `Expires: ${c.not_after}`,
    ...(c.template ? [`Template: ${c.template.name}`] : []),
  ]
  switch (delivery.event) {
    case 'expiring':
      return { subject: `Certificate ${certificateName(cert!)} expires ${inDays(p.days_left ?? 0)}`, lines: certLines(cert!), url: cert!.url }
    case 'issued':
      return { subject: `Certificate ${certificateName(cert!)} issued`, lines: certLines(cert!), url: cert!.url }
    case 'revoked':
      if (cert) return { subject: `Certificate ${certificateName(cert)} revoked`, lines: [...certLines(cert), `Reason: ${p.reason ?? 'unspecified'}`], url: cert.url }
      return { subject: `CA ${ca!.name} revoked`, lines: [`CA: ${ca!.name}`, `Reason: ${p.reason ?? 'unspecified'}`], url: ca!.url }
    case 'ca_expiring':
      return { subject: `CA ${ca!.name} expires ${inDays(p.days_left ?? 0)}`, lines: [`CA: ${ca!.name}`, `Expires: ${ca!.not_after}`], url: ca!.url }
    case 'ssh_host_expiring': {
      const host = p.ssh_host!
      return {
        subject: `SSH host certificate of ${host.name} expires ${inDays(p.days_left ?? 0)}`,
        lines: [`Host: ${host.name}`, `Host names: ${host.hostnames.join(', ')}`, `Serial: ${host.serial}`, `Expires: ${host.not_after}`],
        url: host.url ?? undefined,
      }
    }
    case 'crl_failed':
      return { subject: `The CRL of CA ${ca!.name} could not be published`, lines: [`CA: ${ca!.name}`, `Error: ${p.error ?? 'unknown'}`], url: ca!.url }
    default:
      return { subject: 'Alert', lines: [] }
  }
}

// ---------------------------------------------------------------------------------------------
// Matching and queueing

function certificateMatches(rule: AlertRuleRow, cert: { source: string; ca_id: string | null; template_id: string | null }): boolean {
  const { filter } = rule
  if (cert.source === 'import' || !cert.ca_id) return filter.include_imported
  return (!filter.ca_ids.length || filter.ca_ids.includes(cert.ca_id)) && (!filter.template_ids.length || (!!cert.template_id && filter.template_ids.includes(cert.template_id)))
}

const caMatches = (rule: AlertRuleRow, ca_id: string) => !rule.filter.ca_ids.length || rule.filter.ca_ids.includes(ca_id)

interface PlannedAlert {
  rule: AlertRuleRow
  subject_type: string
  subject_id: string
  /** What makes this alert unique for its rule and channel: the subject and the threshold. */
  key: string
  payload: Record<string, unknown>
}

/**
 * Store one delivery per channel of each planned alert, skipping those whose dedupe key exists
 * (it was sent before), and queue the new ones.
 */
async function queueDeliveries(ctx: Context, planned: PlannedAlert[]): Promise<number> {
  const values = planned.flatMap((alert) =>
    alert.rule.channel_ids.map((channel_id) => ({
      rule_id: alert.rule.id,
      channel_id,
      event: alert.rule.event,
      subject_type: alert.subject_type,
      subject_id: alert.subject_id,
      dedupe_key: `${alert.rule.id}:${channel_id}:${alert.key}`,
      payload: alert.payload,
    })),
  )
  if (!values.length) return 0
  const rows = await ctx.db.insert(schema.alertDeliveries).values(values).onConflictDoNothing({ target: schema.alertDeliveries.dedupe_key }).returning({ id: schema.alertDeliveries.id })
  for (const row of rows) ctx.enqueue({ name: 'alerts.deliver', data: { delivery_id: row.id } })
  return rows.length
}

async function enabledRules(db: Executor, events: AlertEvent[]): Promise<AlertRuleRow[]> {
  return db
    .select()
    .from(schema.alertRules)
    .where(and(eq(schema.alertRules.enabled, true), inArray(schema.alertRules.event, events)))
}

/** Audit events that can cause an alert, and which alert event they are. */
const EVENT_TRIGGERS: Record<string, AlertEvent> = {
  'certificates.issue': 'issued',
  'certificates.renew': 'issued',
  'certificates.revoke': 'revoked',
  'certificate_authorities.revoke': 'revoked',
  'certificate_authorities.mark_compromised': 'revoked',
  'crls.publish_failed': 'crl_failed',
}

/**
 * Called for every audit event once it is stored (and its transaction committed): queues a
 * job that matches the event against the alert rules, so the request is not slowed down and a
 * rule lookup that fails is retried.
 */
export function queueEventAlerts(ctx: Context, event: EventRow): void {
  if (EVENT_TRIGGERS[event.name] && event.subject_id) ctx.enqueue({ name: 'alerts.event', data: { event_id: event.id } })
}

/** The job behind `queueEventAlerts`: one delivery per matching rule and channel, deduplicated. */
export async function dispatchEventAlerts(ctx: Context, event_id: string): Promise<{ queued: number }> {
  const [event] = await ctx.db.select().from(schema.events).where(eq(schema.events.id, event_id))
  const kind = event && EVENT_TRIGGERS[event.name]
  if (!event || !kind || !event.subject_id) return { queued: 0 }
  const rules = await enabledRules(ctx.db, [kind])
  if (!rules.length) return { queued: 0 }

  const planned: PlannedAlert[] = []
  if (event.subject_type === 'certificate') {
    const [row] = await loadCertificates(ctx.db, eq(schema.certificates.id, event.subject_id))
    if (!row) return { queued: 0 }
    const certificate = certificateFacts(ctx, row)
    const reason = typeof event.data.reason === 'string' ? event.data.reason : undefined
    for (const rule of rules) {
      if (!certificateMatches(rule, row)) continue
      planned.push({ rule, subject_type: 'certificate', subject_id: row.id, key: `${kind}:certificate:${row.id}`, payload: { certificate, ...(reason ? { reason } : {}) } })
    }
  } else if (event.subject_type === 'certificate_authority') {
    const cas = schema.certificateAuthorities
    const [ca] = await ctx.db.select({ id: cas.id, name: cas.name, slug: cas.slug, not_after: cas.not_after }).from(cas).where(eq(cas.id, event.subject_id))
    if (!ca) return { queued: 0 }
    const facts = caFacts(ctx, ca)
    // A CRL that keeps failing is reported once a day, not on every rebuild attempt.
    const key = kind === 'crl_failed' ? `${kind}:${ca.id}:${event.created_at.toISOString().slice(0, 10)}` : `${kind}:certificate_authority:${ca.id}`
    const extra = kind === 'crl_failed' ? { error: event.data.error } : { reason: event.data.reason }
    for (const rule of rules) {
      if (caMatches(rule, ca.id)) planned.push({ rule, subject_type: 'certificate_authority', subject_id: ca.id, key, payload: { certificate_authority: facts, ...extra } })
    }
  }

  return { queued: await queueDeliveries(ctx, planned) }
}

/** The smallest threshold the remaining time has reached, or null when none has been. */
export function thresholdFor(thresholds: readonly number[], not_after: Date, now: Date): number | null {
  const left = (not_after.getTime() - now.getTime()) / DAY_MS
  const reached = thresholds.filter((days) => left <= days)
  return reached.length ? Math.min(...reached) : null
}

/**
 * The daily expiry scan: for each enabled `expiring` and `ca_expiring` rule, every live
 * certificate or CA inside a warning threshold gets an alert for the nearest threshold it has
 * reached. The dedupe key holds that threshold, so each warning goes out once however often the
 * scan runs, and a certificate that crosses the next threshold gets the next one.
 */
export async function scanExpiryAlerts(ctx: Context, now = new Date()): Promise<{ queued: number }> {
  const rules = await enabledRules(ctx.db, ['expiring', 'ca_expiring', 'ssh_host_expiring'])
  const horizon = (event: AlertEvent) => Math.max(0, ...rules.filter((r) => r.event === event).flatMap((r) => r.days_before))
  const planned: PlannedAlert[] = []
  const daysLeft = (not_after: Date) => Math.max(0, Math.ceil((not_after.getTime() - now.getTime()) / DAY_MS))

  const certDays = horizon('expiring')
  if (certDays > 0) {
    const c = schema.certificates
    // Superseded and revoked certificates need no warning: they are replaced or out of use.
    const rows = await loadCertificates(ctx.db, and(eq(c.status, 'active'), gt(c.not_after, now), lte(c.not_after, new Date(now.getTime() + certDays * DAY_MS))))
    for (const rule of rules.filter((r) => r.event === 'expiring')) {
      for (const row of rows) {
        const threshold = thresholdFor(rule.days_before, row.not_after, now)
        if (threshold === null || !certificateMatches(rule, row)) continue
        planned.push({
          rule,
          subject_type: 'certificate',
          subject_id: row.id,
          key: `expiring:certificate:${row.id}:${threshold}d`,
          payload: { certificate: certificateFacts(ctx, row), days_left: daysLeft(row.not_after), threshold_days: threshold },
        })
      }
    }
  }

  const caDays = horizon('ca_expiring')
  if (caDays > 0) {
    const cas = schema.certificateAuthorities
    const rows = await ctx.db
      .select({ id: cas.id, name: cas.name, slug: cas.slug, not_after: cas.not_after, active_cert_id: cas.active_cert_id })
      .from(cas)
      .where(and(eq(cas.status, 'active'), gt(cas.not_after, now), lte(cas.not_after, new Date(now.getTime() + caDays * DAY_MS))))
    for (const rule of rules.filter((r) => r.event === 'ca_expiring')) {
      for (const ca of rows) {
        const threshold = ca.not_after && thresholdFor(rule.days_before, ca.not_after, now)
        if (!threshold || !ca.active_cert_id || !caMatches(rule, ca.id)) continue
        // Keyed by the CA certificate, so a renewed CA is warned about again before its new end.
        planned.push({
          rule,
          subject_type: 'certificate_authority',
          subject_id: ca.id,
          key: `ca_expiring:ca_certificate:${ca.active_cert_id}:${threshold}d`,
          payload: { certificate_authority: caFacts(ctx, ca), days_left: daysLeft(ca.not_after!), threshold_days: threshold },
        })
      }
    }
  }
  const sshDays = horizon('ssh_host_expiring')
  if (sshDays > 0) {
    // A certificate that a newer one for the same key has replaced needs no warning.
    const c = schema.sshCertificates
    const newer = alias(schema.sshCertificates, 'newer_ssh_certificates')
    const rows = await ctx.db
      .select({ cert: c, host: { id: schema.sshHosts.id, name: schema.sshHosts.name, hostnames: schema.sshHosts.hostnames } })
      .from(c)
      .innerJoin(schema.sshHosts, eq(schema.sshHosts.id, c.host_id))
      .where(
        and(
          eq(c.kind, 'host'),
          isNull(c.revoked_at),
          gt(c.valid_before, now),
          lte(c.valid_before, new Date(now.getTime() + sshDays * DAY_MS)),
          notExists(
            ctx.db
              .select({ one: sql`1` })
              .from(newer)
              .where(and(eq(newer.host_id, c.host_id), eq(newer.fingerprint, c.fingerprint), isNull(newer.revoked_at), gt(newer.valid_before, c.valid_before))),
          ),
        ),
      )
    for (const rule of rules.filter((r) => r.event === 'ssh_host_expiring')) {
      for (const { cert, host } of rows) {
        const threshold = thresholdFor(rule.days_before, cert.valid_before, now)
        if (threshold === null) continue
        planned.push({
          rule,
          subject_type: 'ssh_certificate',
          subject_id: cert.id,
          key: `ssh_host_expiring:ssh_certificate:${cert.id}:${threshold}d`,
          payload: {
            ssh_host: { id: host.id, name: host.name, hostnames: host.hostnames, serial: cert.serial.toString(), not_after: cert.valid_before.toISOString(), url: `${ctx.base_url}/ssh/hosts/${host.id}` } satisfies SshHostFacts,
            days_left: daysLeft(cert.valid_before),
            threshold_days: threshold,
          },
        })
      }
    }
  }
  return { queued: await queueDeliveries(ctx, planned) }
}

// ---------------------------------------------------------------------------------------------
// Sending

/** A delivery that failed with a message fit for the history: no secrets, no internals. */
class DeliveryFailure extends Error {}

function errorText(error: unknown): string {
  if (error instanceof DeliveryFailure) return error.message
  const named = error as { name?: string; cause?: { code?: string } }
  if (named?.name === 'TimeoutError' || named?.name === 'AbortError') return `No answer within ${WEBHOOK_TIMEOUT_MS / 1000} s`
  if (named?.cause?.code) return `Connection failed (${named.cause.code})`
  if (error instanceof TypeError) return 'Connection failed'
  return 'Delivery failed'
}

/** Reads at most `limit` bytes of a response body and drops the rest. */
async function readCapped(response: Response, limit: number): Promise<string> {
  if (!response.body) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (size < limit) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      size += value.byteLength
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
  return new TextDecoder().decode(Buffer.concat(chunks).subarray(0, limit))
}

/**
 * POST the delivery as JSON, signed with the channel's secret. The body is
 * `{ id, event, timestamp, test, data }`; `timestamp` (Unix seconds) is the moment of this attempt
 * and is repeated in `X-Certifly-Timestamp`. Redirects are not followed, the answer must come
 * within 10 seconds, and only its first few KB are read.
 */
async function sendWebhook(ctx: Context, config: { url: string; secret_enc: string }, delivery: AlertDeliveryRow) {
  const secret = decryptSecret(ctx.secret_key, config.secret_enc)
  const timestamp = Math.floor(Date.now() / 1000)
  const event = delivery.test ? 'test' : delivery.event!
  const body = JSON.stringify({ id: delivery.id, event, timestamp, test: delivery.test, data: delivery.payload })
  const response = await fetch(config.url, {
    method: 'POST',
    redirect: 'manual',
    signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    headers: {
      'content-type': 'application/json',
      'user-agent': 'certifly-webhook',
      [WEBHOOK_HEADERS.signature]: webhookSignature(secret, body),
      [WEBHOOK_HEADERS.timestamp]: String(timestamp),
      [WEBHOOK_HEADERS.event]: event,
      [WEBHOOK_HEADERS.delivery]: delivery.id,
    },
    body,
  })
  const answer = await readCapped(response, WEBHOOK_RESPONSE_LIMIT)
  if (response.status >= 200 && response.status < 300) return
  // eslint-disable-next-line no-control-regex
  const snippet = answer.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 200)
  const redirect = response.status >= 300 && response.status < 400 ? ' (redirects are not followed)' : ''
  throw new DeliveryFailure(`HTTP ${response.status}${redirect}${snippet ? `: ${snippet}` : ''}`)
}

async function sendEmail(ctx: Context, config: { recipients: string[] }, delivery: AlertDeliveryRow) {
  if (!ctx.mailer.delivers) throw new DeliveryFailure('This instance cannot send mail (SMTP_URL is not set)')
  const alert = describeAlert(delivery)
  const mail = renderMail({
    heading: alert.subject,
    body: alert.lines,
    ...(alert.url ? { action: { label: 'Open in certifly', url: alert.url } } : {}),
    footer: 'You get this mail because an alert rule in certifly sends to this address.',
  })
  for (const to of config.recipients) await ctx.mailer.send({ to, subject: `[certifly] ${alert.subject}`, ...mail })
}

/**
 * Send one delivery: the `alerts.deliver` job. Each attempt is counted, and a failure is stored
 * with its message. Unless this was the last attempt (or `retry: false`), the failure is thrown
 * again so pg-boss retries it later with a growing delay. A delivery already sent is not sent
 * again, so a retried job does no harm.
 */
export async function deliverAlert(ctx: Context, id: string, options: { retry?: boolean } = {}): Promise<AlertDeliveryRow | null> {
  const d = schema.alertDeliveries
  const [delivery] = await ctx.db
    .update(d)
    .set({ attempts: sql`${d.attempts} + 1`, last_attempt_at: new Date() })
    .where(and(eq(d.id, id), ne(d.status, 'sent')))
    .returning()
  if (!delivery) return null
  const [channel] = delivery.channel_id ? await ctx.db.select().from(schema.alertChannels).where(eq(schema.alertChannels.id, delivery.channel_id)) : []

  let failure: string | null = null
  if (!channel) failure = 'The channel was deleted'
  else {
    try {
      if ('recipients' in channel.config) await sendEmail(ctx, channel.config, delivery)
      else await sendWebhook(ctx, channel.config, delivery)
    } catch (error) {
      failure = errorText(error).slice(0, MAX_ERROR_LENGTH)
    }
  }

  if (failure === null) {
    const [sent] = await ctx.db.update(d).set({ status: 'sent', sent_at: new Date(), last_error: null }).where(eq(d.id, id)).returning()
    return sent!
  }
  const final = !channel || options.retry === false || delivery.attempts >= ALERT_MAX_ATTEMPTS
  const [failed] = await ctx.db
    .update(d)
    .set({ status: final ? 'failed' : 'retrying', last_error: failure })
    .where(eq(d.id, id))
    .returning()
  if (!final) throw new Error(`Alert delivery ${id} failed: ${failure}`)
  return failed!
}
