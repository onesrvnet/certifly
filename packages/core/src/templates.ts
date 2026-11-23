import { type Executor, type LeafExtendedKeyUsage, type LeafKeyAlgorithm, type LeafKeyUsage, type SanKind, schema, type SubjectField } from '@certifly/db'
import type { KeyAlgorithm } from '@certifly/keyvault'
import {
  type ExtendedKeyUsageName,
  formatCidr,
  isValidDomainPattern,
  type KeyUsageName,
  normalizeDn,
  parseCidr,
  PkiError,
  ruleConstraintProblems,
} from '@certifly/pki'
import { and, count, eq, inArray, type SQL } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import { CA_SLUG_PATTERN, type CaRow } from './cas'
import type { Context } from './context'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, templatePolicy } from './policies'
import { checkTagIds, replaceTags, type TagSummary, templateTagsOf } from './tags'

export type TemplateRow = typeof schema.templates.$inferSelect
export type TemplateStatus = TemplateRow['status']

export const LEAF_KEY_ALGORITHMS = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'] as const satisfies readonly KeyAlgorithm[]
export const LEAF_KEY_USAGES = ['digital_signature', 'non_repudiation', 'key_encipherment', 'data_encipherment', 'key_agreement'] as const satisfies readonly (KeyUsageName & LeafKeyUsage)[]
/** RFC 5480 §3: EC keys cannot encrypt, so these usages are only set on certificates for RSA keys. */
export const RSA_ONLY_KEY_USAGES: readonly LeafKeyUsage[] = ['key_encipherment', 'data_encipherment']
/** RFC 5280 §4.2.1.12 key purposes a template can set. */
export const EXTENDED_KEY_USAGES = ['server_auth', 'client_auth', 'code_signing', 'email_protection', 'time_stamping', 'ocsp_signing'] as const satisfies readonly ExtendedKeyUsageName[]
export const SAN_TYPES = ['dns', 'ip', 'email', 'uri'] as const satisfies readonly SanKind[]
export const SUBJECT_FIELDS = ['CN', 'O', 'OU', 'C', 'ST', 'L', 'E'] as const satisfies readonly SubjectField[]

const DAY = 24 * 60 * 60
/** Shorter lifetimes than this are more likely a typo than a plan. */
export const MIN_TTL_SECONDS = 5 * 60
export const MAX_TEMPLATE_TTL_SECONDS = 3650 * DAY
const MAX_RULES = 100

/** Everything a template decides, apart from its name and the CA it is bound to. */
export interface TemplateSettings {
  allowed_san_types: SanKind[]
  allowed_dns: string[]
  allowed_ips: string[]
  allow_wildcards: boolean
  require_san: boolean
  require_common_name: boolean
  subject_defaults: Partial<Record<SubjectField, string>>
  allowed_subject_fields: SubjectField[]
  key_algorithms: LeafKeyAlgorithm[]
  max_ttl_seconds: number
  default_ttl_seconds: number
  key_usages: LeafKeyUsage[]
  extended_key_usages: LeafExtendedKeyUsage[]
  allow_server_keygen: boolean
  allow_acme: boolean
  allow_est: boolean
  renew_before_days: number
}

export type TemplatePresetId = 'webserver_tls' | 'mtls_server' | 'mtls_client' | 'server_client'

const ALL_ALGORITHMS: LeafKeyAlgorithm[] = [...LEAF_KEY_ALGORITHMS]
const serverDefaults = {
  // IP SANs need CIDRs to match, so they start switched off; enabling them asks for ranges.
  allowed_san_types: ['dns'],
  allowed_dns: [],
  allowed_ips: [],
  allow_wildcards: false,
  require_san: true,
  require_common_name: false,
  subject_defaults: {},
  allowed_subject_fields: ['CN'],
  key_algorithms: ALL_ALGORITHMS,
  max_ttl_seconds: 397 * DAY,
  default_ttl_seconds: 90 * DAY,
  // keyEncipherment applies to RSA keys only (RSA key exchange in TLS 1.2); it is dropped for EC keys.
  key_usages: ['digital_signature', 'key_encipherment'],
  allow_server_keygen: true,
  allow_acme: false,
  allow_est: false,
  renew_before_days: 30,
} satisfies Omit<TemplateSettings, 'extended_key_usages'>

/**
 * The built-in starting points. An admin picks one, then edits the values; nothing links a
 * template to its preset afterwards.
 */
export const TEMPLATE_PRESETS: Record<TemplatePresetId, TemplateSettings> = {
  webserver_tls: { ...serverDefaults, extended_key_usages: ['server_auth'] },
  mtls_server: { ...serverDefaults, extended_key_usages: ['server_auth'] },
  mtls_client: {
    ...serverDefaults,
    allowed_san_types: ['dns', 'email', 'uri'],
    require_san: false,
    require_common_name: true,
    allowed_subject_fields: ['CN', 'OU'],
    max_ttl_seconds: 90 * DAY,
    default_ttl_seconds: 30 * DAY,
    key_usages: ['digital_signature'],
    extended_key_usages: ['client_auth'],
    renew_before_days: 7,
  },
  server_client: { ...serverDefaults, extended_key_usages: ['server_auth', 'client_auth'] },
}

export const TEMPLATE_PRESET_IDS = Object.keys(TEMPLATE_PRESETS) as TemplatePresetId[]

// ---------------------------------------------------------------------------------------------
// Validation

const subjectOf = (id: string) => ({ type: 'template', id })

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)]
}

function subsetOf<T extends string>(values: readonly unknown[], allowed: readonly T[], what: string, code = 'validation_error'): T[] {
  if (!Array.isArray(values)) throw new ValidationError(`${what} must be a list`, code)
  const bad = values.filter((v) => !allowed.includes(v as T))
  if (bad.length) throw new ValidationError(`${what}: unknown value ${bad.map(String).join(', ')}`, code)
  return unique(values as T[])
}

function checkDomainPatterns(values: readonly string[]): string[] {
  if (values.length > MAX_RULES) throw new ValidationError(`At most ${MAX_RULES} domain patterns`, 'invalid_domain_pattern')
  const normalized = values.map((v) => String(v).trim().toLowerCase().replace(/\.$/, ''))
  const invalid = normalized.filter((v) => !isValidDomainPattern(v))
  if (invalid.length) {
    throw new ValidationError(`Not a valid domain pattern: ${invalid.join(', ')}. Use api.example.com, *.example.com or **.example.com.`, 'invalid_domain_pattern', { invalid })
  }
  return unique(normalized)
}

function checkCidrs(values: readonly string[]): string[] {
  if (values.length > MAX_RULES) throw new ValidationError(`At most ${MAX_RULES} IP ranges`, 'invalid_cidr')
  const invalid: string[] = []
  const normalized: string[] = []
  for (const value of values) {
    const cidr = parseCidr(String(value))
    if (cidr) normalized.push(formatCidr(cidr))
    else invalid.push(String(value))
  }
  if (invalid.length) throw new ValidationError(`Not a valid CIDR (host bits must be zero): ${invalid.join(', ')}`, 'invalid_cidr', { invalid })
  return unique(normalized)
}

function checkSubjectDefaults(defaults: Partial<Record<string, string>>): Partial<Record<SubjectField, string>> {
  if (!defaults || typeof defaults !== 'object' || Array.isArray(defaults)) throw new ValidationError('subject_defaults must be an object', 'invalid_subject_defaults')
  const out: Partial<Record<SubjectField, string>> = {}
  for (const [field, raw] of Object.entries(defaults)) {
    if (field === 'CN') throw new ValidationError('The common name comes from each request, not from the template', 'invalid_subject_defaults')
    if (!SUBJECT_FIELDS.includes(field as SubjectField)) throw new ValidationError(`Unknown subject field: ${field}`, 'invalid_subject_defaults')
    const value = typeof raw === 'string' ? raw.trim() : ''
    if (value) out[field as SubjectField] = value
  }
  const attributes = Object.entries(out).map(([type, value]) => ({ type, value: value! }))
  try {
    if (attributes.length) normalizeDn(attributes)
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, 'invalid_subject_defaults')
    throw error
  }
  return out
}

function checkTtl(settings: Pick<TemplateSettings, 'max_ttl_seconds' | 'default_ttl_seconds'>) {
  const { max_ttl_seconds: max, default_ttl_seconds: def } = settings
  if (!Number.isInteger(max) || max < MIN_TTL_SECONDS || max > MAX_TEMPLATE_TTL_SECONDS) {
    throw new ValidationError(`max_ttl_seconds must be from ${MIN_TTL_SECONDS} to ${MAX_TEMPLATE_TTL_SECONDS}`, 'invalid_ttl')
  }
  if (!Number.isInteger(def) || def < MIN_TTL_SECONDS || def > max) throw new ValidationError('default_ttl_seconds must be at least 5 minutes and at most max_ttl_seconds', 'invalid_ttl')
}

/** Validates and normalises the settings on their own, without looking at the CA. */
export function checkTemplateSettings(input: TemplateSettings): TemplateSettings {
  const allowed_san_types = subsetOf(input.allowed_san_types, SAN_TYPES, 'allowed_san_types')
  if (!allowed_san_types.length) throw new ValidationError('Allow at least one SAN type', 'san_types_required')
  const allowed_dns = checkDomainPatterns(input.allowed_dns ?? [])
  const allowed_ips = checkCidrs(input.allowed_ips ?? [])
  // An empty rule list allows nothing: a template never means "any name".
  if (allowed_san_types.some((t) => t !== 'ip') && !allowed_dns.length) {
    throw new ValidationError('Add at least one domain pattern: DNS names, email domains and URI hosts are matched against them', 'allowed_dns_required')
  }
  if (allowed_san_types.includes('ip') && !allowed_ips.length) throw new ValidationError('Add at least one IP range for IP SANs', 'allowed_ips_required')

  const allowed_subject_fields = subsetOf(input.allowed_subject_fields, SUBJECT_FIELDS, 'allowed_subject_fields')
  if (input.require_common_name && !allowed_subject_fields.includes('CN')) {
    throw new ValidationError('A required common name must also be an allowed subject field', 'common_name_not_allowed')
  }
  const subject_defaults = checkSubjectDefaults(input.subject_defaults ?? {})

  const key_algorithms = subsetOf(input.key_algorithms, LEAF_KEY_ALGORITHMS, 'key_algorithms', 'unsupported_key')
  if (!key_algorithms.length) throw new ValidationError('Allow at least one key algorithm', 'unsupported_key')
  checkTtl(input)

  const key_usages = subsetOf(input.key_usages, LEAF_KEY_USAGES, 'key_usages', 'invalid_key_usages')
  const ecUsable = key_usages.filter((u) => !RSA_ONLY_KEY_USAGES.includes(u))
  if (!key_usages.length || (key_algorithms.some((a) => a.startsWith('ecdsa')) && !ecUsable.length)) {
    throw new ValidationError('Key usage needs at least one usage that EC keys can have, such as digitalSignature', 'invalid_key_usages')
  }
  const extended_key_usages = subsetOf(input.extended_key_usages, EXTENDED_KEY_USAGES, 'extended_key_usages', 'invalid_extended_key_usages')
  if (!extended_key_usages.length) throw new ValidationError('Pick at least one extended key usage', 'invalid_extended_key_usages')
  if (extended_key_usages.length !== input.extended_key_usages.length) throw new ValidationError('An extended key usage is listed twice', 'invalid_extended_key_usages')

  if (!Number.isInteger(input.renew_before_days) || input.renew_before_days < 0 || input.renew_before_days > 365) {
    throw new ValidationError('renew_before_days must be from 0 to 365')
  }
  return {
    allowed_san_types,
    allowed_dns,
    allowed_ips,
    allow_wildcards: !!input.allow_wildcards,
    require_san: !!input.require_san,
    require_common_name: !!input.require_common_name,
    subject_defaults,
    allowed_subject_fields,
    key_algorithms,
    max_ttl_seconds: input.max_ttl_seconds,
    default_ttl_seconds: input.default_ttl_seconds,
    key_usages,
    extended_key_usages,
    allow_server_keygen: !!input.allow_server_keygen,
    allow_acme: !!input.allow_acme,
    allow_est: !!input.allow_est,
    renew_before_days: input.renew_before_days,
  }
}

/**
 * The CA a template is bound to must be active (it can sign), and every rule must lie inside its
 * name constraints, so a template never offers names the CA cannot sign. A root is allowed; the
 * presenter flags it so the UI can warn.
 */
async function loadBindableCa(db: Executor, ca_id: string, settings: TemplateSettings): Promise<CaRow> {
  const [ca] = await db.select().from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.id, ca_id))
  if (!ca) throw new NotFoundError('Certificate authority not found', 'ca_not_found')
  if (ca.status === 'disabled') throw new ConflictError('The CA is disabled', 'ca_disabled')
  if (ca.status !== 'active' || !ca.active_cert_id) throw new ConflictError('The CA must be active to issue certificates', 'ca_not_active')
  if (ca.name_constraints) {
    const problems = ruleConstraintProblems(ca.name_constraints, { dns: settings.allowed_dns, ip: settings.allowed_ips })
    if (problems.length) {
      throw new ValidationError(
        `Outside the CA's name constraints: ${problems.map((p) => p.rule).join(', ')}`,
        'template_outside_name_constraints',
        { problems },
      )
    }
  }
  return ca
}

function checkName(name: string): string {
  const trimmed = String(name ?? '').trim()
  if (!trimmed || trimmed.length > 100) throw new ValidationError('The name must be 1 to 100 characters')
  return trimmed
}

// ---------------------------------------------------------------------------------------------
// Create, update, archive

export interface CreateTemplateInput extends Partial<TemplateSettings> {
  name: string
  slug: string
  description?: string
  ca_id: string
  /** Fills every setting the input leaves out. Without it, every setting must be given. */
  preset?: TemplatePresetId
  /** Default tags, copied onto each certificate issued with the template. */
  tag_ids?: string[]
}

const SETTING_KEYS = Object.keys(TEMPLATE_PRESETS.webserver_tls) as (keyof TemplateSettings)[]

/**
 * Create a template bound to an active CA. Settings left out come from `preset`. Domain
 * patterns and CIDRs must be valid and inside the CA's name constraints. Admins only, from a
 * recently re-authenticated session.
 */
export async function createTemplate(ctx: Context, actor: Actor, input: CreateTemplateInput): Promise<TemplateRow> {
  authorize(templatePolicy, actor, 'create', undefined)
  assertStepUp(actor)
  const name = checkName(input.name)
  if (!CA_SLUG_PATTERN.test(input.slug ?? '')) throw new ValidationError('The slug must be lowercase letters, digits and hyphens (at most 64)', 'invalid_slug')
  if (input.preset && !TEMPLATE_PRESETS[input.preset]) throw new ValidationError('Unknown preset', 'unknown_preset')
  const base = input.preset ? TEMPLATE_PRESETS[input.preset] : null
  const merged = {} as Record<string, unknown>
  for (const key of SETTING_KEYS) {
    const value = input[key] ?? base?.[key]
    if (value === undefined) throw new ValidationError(`${key} is required without a preset`)
    merged[key] = value
  }
  const settings = checkTemplateSettings(merged as unknown as TemplateSettings)
  const ca = await loadBindableCa(ctx.db, input.ca_id, settings)
  const tag_ids = await checkTagIds(ctx.db, input.tag_ids ?? [])

  try {
    return await withTransaction(ctx, async (tx) => {
      const [row] = await tx
        .insert(schema.templates)
        .values({ name, slug: input.slug, description: input.description?.trim() ?? '', ca_id: ca.id, ...settings })
        .returning()
      await replaceTags(tx, schema.templateTags, row!.id, tag_ids)
      await recordEvent(ctx, eventFor(actor, 'templates.create', subjectOf(row!.id), { slug: row!.slug, ca_id: ca.id, preset: input.preset ?? null, tag_ids }), tx)
      return row!
    })
  } catch (error) {
    if (isUniqueViolation(error, 'templates_slug_unique')) throw new ConflictError('Another template already uses this slug', 'template_slug_taken')
    throw error
  }
}

export interface UpdateTemplateInput extends Partial<TemplateSettings> {
  name?: string
  description?: string
  /** Moves the template to another CA; its rules must fit that CA too. */
  ca_id?: string
  /** Replaces the default tags. Certificates already issued keep theirs. */
  tag_ids?: string[]
}

async function findTemplate(db: Executor, id: string, lock = false): Promise<TemplateRow> {
  const query = db.select().from(schema.templates).where(eq(schema.templates.id, id))
  const [row] = lock ? await query.for('update') : await query
  if (!row) throw new NotFoundError('Template not found')
  return row
}

const settingsOf = (row: TemplateRow): TemplateSettings => {
  const out = {} as Record<string, unknown>
  for (const key of SETTING_KEYS) out[key] = row[key]
  return out as unknown as TemplateSettings
}

/**
 * Change a template. The result is validated as a whole, against the CA it ends up bound to.
 * The slug never changes. Certificates already issued keep what they were issued with.
 * Archived templates cannot be changed. Admins only, from a recently re-authenticated session.
 */
export async function updateTemplate(ctx: Context, actor: Actor, id: string, input: UpdateTemplateInput): Promise<TemplateRow> {
  authorize(templatePolicy, actor, 'update', undefined)
  assertStepUp(actor)
  const current = await findTemplate(ctx.db, id)
  if (current.status === 'archived') throw new ConflictError('The template is archived', 'template_archived')

  const patch = {} as Record<string, unknown>
  for (const key of SETTING_KEYS) if (input[key] !== undefined) patch[key] = input[key]
  const settings = checkTemplateSettings({ ...settingsOf(current), ...patch } as TemplateSettings)
  const ca_id = input.ca_id ?? current.ca_id
  await loadBindableCa(ctx.db, ca_id, settings)
  const name = input.name !== undefined ? checkName(input.name) : current.name
  const description = input.description !== undefined ? input.description.trim() : current.description
  const tag_ids = input.tag_ids !== undefined ? await checkTagIds(ctx.db, input.tag_ids) : undefined

  return withTransaction(ctx, async (tx) => {
    const locked = await findTemplate(tx, id, true)
    if (locked.status === 'archived') throw new ConflictError('The template is archived', 'template_archived')
    const values = { name, description, ca_id, ...settings }
    const changed = Object.keys(values).filter((key) => JSON.stringify(values[key as keyof typeof values]) !== JSON.stringify(locked[key as keyof TemplateRow]))
    const [row] = await tx.update(schema.templates).set(values).where(eq(schema.templates.id, id)).returning()
    const tags = tag_ids ? await replaceTags(tx, schema.templateTags, id, tag_ids) : { added: [], removed: [] }
    if (tags.added.length || tags.removed.length) changed.push('tag_ids')
    await recordEvent(ctx, eventFor(actor, 'templates.update', subjectOf(id), { changed, ca_id, added_tag_ids: tags.added, removed_tag_ids: tags.removed }), tx)
    return row!
  })
}

/**
 * Archive a template: nothing more is issued or renewed with it. Certificates it issued stay
 * as they are. Archiving an archived template changes nothing.
 */
export async function archiveTemplate(ctx: Context, actor: Actor, id: string): Promise<TemplateRow> {
  authorize(templatePolicy, actor, 'archive', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const template = await findTemplate(tx, id, true)
    if (template.status === 'archived') return template
    const [row] = await tx.update(schema.templates).set({ status: 'archived', archived_at: new Date() }).where(eq(schema.templates.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'templates.archive', subjectOf(id), { slug: template.slug }), tx)
    return row!
  })
}

// ---------------------------------------------------------------------------------------------
// Read

/** The CA fields a template's page and the issue form need. */
export type TemplateCa = Pick<CaRow, 'id' | 'name' | 'slug' | 'status' | 'signing' | 'not_after' | 'name_constraints'>

export interface TemplateWithCa {
  template: TemplateRow
  ca: TemplateCa
  /** Default tags for certificates it issues. */
  tags: TagSummary[]
  /** Where EST clients enroll (RFC 7030); null unless the template allows EST. */
  est_base_url: string | null
  /** The ACME directory of the template; null unless it allows ACME. */
  acme_directory_url: string | null
  /** ACME accounts registered with the template. */
  acme_account_count: number
}

/** The ACME directory of a template, where clients start. */
export const acmeDirectoryUrl = (ctx: Context, template: Pick<TemplateRow, 'slug' | 'allow_acme'>) =>
  template.allow_acme ? `${ctx.pki_base_url}/acme/${template.slug}/directory` : null

/** How many ACME accounts each template has. */
async function acmeAccountCounts(db: Executor, ids: string[]): Promise<Map<string, number>> {
  if (!ids.length) return new Map()
  const a = schema.acmeAccounts
  const rows = await db.select({ template_id: a.template_id, count: count() }).from(a).where(inArray(a.template_id, ids)).groupBy(a.template_id)
  return new Map(rows.map((row) => [row.template_id, row.count]))
}

/** The EST root of a template: clients append `/cacerts`, `/simpleenroll` and so on. */
export const estBaseUrl = (ctx: Context, template: Pick<TemplateRow, 'slug' | 'allow_est'>) =>
  template.allow_est ? `${ctx.base_url.replace(/\/+$/, '')}/.well-known/est/${template.slug}` : null

const caSummary = {
  id: schema.certificateAuthorities.id,
  name: schema.certificateAuthorities.name,
  slug: schema.certificateAuthorities.slug,
  status: schema.certificateAuthorities.status,
  signing: schema.certificateAuthorities.signing,
  not_after: schema.certificateAuthorities.not_after,
  name_constraints: schema.certificateAuthorities.name_constraints,
}

export interface ListTemplatesInput extends CursorInput {
  ca_id?: string
  status?: TemplateStatus
}

/** Templates alphabetically, each with its CA. */
export async function listTemplates(ctx: Context, actor: Actor, input: ListTemplatesInput) {
  authorize(templatePolicy, actor, 'read', undefined)
  const t = schema.templates
  const filters: (SQL | undefined)[] = []
  if (input.ca_id) filters.push(eq(t.ca_id, input.ca_id))
  if (input.status) filters.push(eq(t.status, input.status))
  const page = keyset(byName(t.name, t.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, template: t, ca: caSummary })
    .from(t)
    .innerJoin(schema.certificateAuthorities, eq(schema.certificateAuthorities.id, t.ca_id))
    .where(and(...filters, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  const tags = await templateTagsOf(ctx.db, result.rows.map((row) => row.template.id))
  const accounts = await acmeAccountCounts(ctx.db, result.rows.map((row) => row.template.id))
  return {
    rows: result.rows.map((row) => ({
      ...row,
      tags: tags.get(row.template.id) ?? [],
      est_base_url: estBaseUrl(ctx, row.template),
      acme_directory_url: acmeDirectoryUrl(ctx, row.template),
      acme_account_count: accounts.get(row.template.id) ?? 0,
    })),
    next_cursor: result.next_cursor,
  } as { rows: TemplateWithCa[]; next_cursor: string | null }
}

/** One template with its CA. */
export async function getTemplate(ctx: Context, actor: Actor, id: string): Promise<TemplateWithCa> {
  authorize(templatePolicy, actor, 'read', undefined)
  const [row] = await ctx.db
    .select({ template: schema.templates, ca: caSummary })
    .from(schema.templates)
    .innerJoin(schema.certificateAuthorities, eq(schema.certificateAuthorities.id, schema.templates.ca_id))
    .where(eq(schema.templates.id, id))
  if (!row) throw new NotFoundError('Template not found')
  const tags = await templateTagsOf(ctx.db, [id])
  const accounts = await acmeAccountCounts(ctx.db, [id])
  return { ...row, tags: tags.get(id) ?? [], est_base_url: estBaseUrl(ctx, row.template), acme_directory_url: acmeDirectoryUrl(ctx, row.template), acme_account_count: accounts.get(id) ?? 0 }
}

/** The built-in presets, for the create form and API clients. */
export function listTemplatePresets(actor: Actor) {
  authorize(templatePolicy, actor, 'read', undefined)
  return TEMPLATE_PRESET_IDS.map((id) => ({ id, ...TEMPLATE_PRESETS[id] }))
}
