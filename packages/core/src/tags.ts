import { type Executor, schema } from '@certifly/db'
import { and, count, eq, inArray, sql } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, tagPolicy } from './policies'

export type TagRow = typeof schema.tags.$inferSelect
export type TagColor = TagRow['color']
/** A tag as certificates and templates carry it. */
export type TagSummary = Pick<TagRow, 'id' | 'name' | 'color'>

export const TAG_COLORS = schema.tagColor.enumValues
export const MAX_TAG_NAME = 50
/** Tags on one certificate or template; more is a mistake. */
export const MAX_TAGS_PER_ITEM = 50

const subjectOf = (id: string) => ({ type: 'tag', id })

function checkName(name: string): string {
  const trimmed = String(name ?? '').trim()
  if (!trimmed || trimmed.length > MAX_TAG_NAME) throw new ValidationError(`The name must be 1 to ${MAX_TAG_NAME} characters`, 'invalid_tag_name')
  return trimmed
}

function checkColor(color: string): TagColor {
  if (!TAG_COLORS.includes(color as TagColor)) throw new ValidationError(`The colour must be one of ${TAG_COLORS.join(', ')}`, 'invalid_tag_color')
  return color as TagColor
}

function nameTaken(error: unknown): never {
  if (isUniqueViolation(error, 'tags_name_lower_idx')) throw new ConflictError('Another tag already has this name', 'tag_name_taken')
  throw error
}

/**
 * The tag ids of a request, without repeats. Every one must exist (`tag_not_found`, with the
 * missing ids in `details.missing`).
 */
export async function checkTagIds(db: Executor, tag_ids: readonly string[]): Promise<string[]> {
  if (!Array.isArray(tag_ids)) throw new ValidationError('tag_ids must be a list')
  const ids = [...new Set(tag_ids)]
  if (ids.length > MAX_TAGS_PER_ITEM) throw new ValidationError(`At most ${MAX_TAGS_PER_ITEM} tags`, 'too_many_tags')
  if (!ids.length) return ids
  const rows = await db.select({ id: schema.tags.id }).from(schema.tags).where(inArray(schema.tags.id, ids))
  const missing = ids.filter((id) => !rows.some((row) => row.id === id))
  if (missing.length) throw new NotFoundError('Tag not found', 'tag_not_found')
  return ids
}

/** The tags of each certificate or template, alphabetically. Items without tags get an empty list. */
async function tagsOf(db: Executor, join: typeof schema.certificateTags | typeof schema.templateTags, ids: readonly string[]): Promise<Map<string, TagSummary[]>> {
  const out = new Map<string, TagSummary[]>(ids.map((id) => [id, []]))
  if (!ids.length) return out
  const owner = 'certificate_id' in join ? join.certificate_id : join.template_id
  const rows = await db
    .select({ owner_id: owner, id: schema.tags.id, name: schema.tags.name, color: schema.tags.color })
    .from(join)
    .innerJoin(schema.tags, eq(schema.tags.id, join.tag_id))
    .where(inArray(owner, [...ids]))
    .orderBy(sql`lower(${schema.tags.name})`, schema.tags.id)
  for (const { owner_id, ...tag } of rows) out.get(owner_id)?.push(tag)
  return out
}

export const certificateTagsOf = (db: Executor, ids: readonly string[]) => tagsOf(db, schema.certificateTags, ids)
export const templateTagsOf = (db: Executor, ids: readonly string[]) => tagsOf(db, schema.templateTags, ids)

/**
 * Replace the tags of a template or certificate. Returns the ids added and removed. Tags
 * deleted meanwhile are skipped rather than failing the change.
 */
export async function replaceTags(
  tx: Executor,
  join: typeof schema.certificateTags | typeof schema.templateTags,
  owner_id: string,
  tag_ids: readonly string[],
): Promise<{ added: string[]; removed: string[] }> {
  const ownerColumn = 'certificate_id' in join ? join.certificate_id : join.template_id
  const ownerKey = 'certificate_id' in join ? 'certificate_id' : 'template_id'
  const current = (await tx.select({ id: join.tag_id }).from(join).where(eq(ownerColumn, owner_id))).map((row) => row.id)
  const removed = current.filter((id) => !tag_ids.includes(id))
  if (removed.length) await tx.delete(join).where(and(eq(ownerColumn, owner_id), inArray(join.tag_id, removed)))
  const wanted = tag_ids.filter((id) => !current.includes(id))
  let added: string[] = []
  if (wanted.length) {
    const existing = await tx.select({ id: schema.tags.id }).from(schema.tags).where(inArray(schema.tags.id, wanted)).for('share')
    added = wanted.filter((id) => existing.some((row) => row.id === id))
    if (added.length) await tx.insert(join).values(added.map((tag_id) => ({ [ownerKey]: owner_id, tag_id }) as never)).onConflictDoNothing()
  }
  return { added, removed }
}

/** Copy the tags of one certificate or template onto a new certificate, as they are right now. */
export async function copyTagsToCertificate(tx: Executor, certificate_id: string, from: { template_id: string } | { certificate_id: string }): Promise<string[]> {
  const source =
    'template_id' in from
      ? tx.select({ certificate_id: sql<string>`${certificate_id}::uuid`.as('certificate_id'), tag_id: schema.templateTags.tag_id }).from(schema.templateTags).where(eq(schema.templateTags.template_id, from.template_id))
      : tx.select({ certificate_id: sql<string>`${certificate_id}::uuid`.as('certificate_id'), tag_id: schema.certificateTags.tag_id }).from(schema.certificateTags).where(eq(schema.certificateTags.certificate_id, from.certificate_id))
  const rows = await tx.insert(schema.certificateTags).select(source).onConflictDoNothing().returning({ tag_id: schema.certificateTags.tag_id })
  return rows.map((row) => row.tag_id)
}

// ---------------------------------------------------------------------------------------------
// The managed list

export interface CreateTagInput {
  name: string
  color?: TagColor
}

/** Add a tag. Names are unique regardless of case. Admins only, from a recently re-authenticated session. */
export async function createTag(ctx: Context, actor: Actor, input: CreateTagInput): Promise<TagRow> {
  authorize(tagPolicy, actor, 'create', undefined)
  assertStepUp(actor)
  const name = checkName(input.name)
  const color = checkColor(input.color ?? 'gray')
  return withTransaction(ctx, async (tx) => {
    const [row] = await tx.insert(schema.tags).values({ name, color }).returning()
    await recordEvent(ctx, eventFor(actor, 'tags.create', subjectOf(row!.id), { name, color }), tx)
    return row!
  }).catch(nameTaken)
}

export interface UpdateTagInput {
  name?: string
  color?: TagColor
}

/** Rename or recolour a tag; certificates and templates carrying it show the change at once. */
export async function updateTag(ctx: Context, actor: Actor, id: string, input: UpdateTagInput): Promise<TagRow> {
  authorize(tagPolicy, actor, 'update', undefined)
  assertStepUp(actor)
  const name = input.name !== undefined ? checkName(input.name) : undefined
  const color = input.color !== undefined ? checkColor(input.color) : undefined
  return withTransaction(ctx, async (tx) => {
    const [current] = await tx.select().from(schema.tags).where(eq(schema.tags.id, id)).for('update')
    if (!current) throw new NotFoundError('Tag not found', 'tag_not_found')
    const values = { name: name ?? current.name, color: color ?? current.color }
    const changed = (Object.keys(values) as (keyof typeof values)[]).filter((key) => values[key] !== current[key])
    if (!changed.length) return current
    const [row] = await tx.update(schema.tags).set(values).where(eq(schema.tags.id, id)).returning()
    await recordEvent(ctx, eventFor(actor, 'tags.update', subjectOf(id), { changed, previous_name: current.name, name: values.name, color: values.color }), tx)
    return row!
  }).catch(nameTaken)
}

export interface DeleteTagResult {
  id: string
  /** How many certificates and templates lost the tag. */
  removed_from_certificates: number
  removed_from_templates: number
}

/** Delete a tag. It comes off every certificate and template that had it. */
export async function deleteTag(ctx: Context, actor: Actor, id: string): Promise<DeleteTagResult> {
  authorize(tagPolicy, actor, 'delete', undefined)
  assertStepUp(actor)
  return withTransaction(ctx, async (tx) => {
    const [tag] = await tx.select().from(schema.tags).where(eq(schema.tags.id, id)).for('update')
    if (!tag) throw new NotFoundError('Tag not found', 'tag_not_found')
    const [certs] = await tx.select({ n: count() }).from(schema.certificateTags).where(eq(schema.certificateTags.tag_id, id))
    const [templates] = await tx.select({ n: count() }).from(schema.templateTags).where(eq(schema.templateTags.tag_id, id))
    // The join rows go with it (on delete cascade).
    await tx.delete(schema.tags).where(eq(schema.tags.id, id))
    const result = { id, removed_from_certificates: certs?.n ?? 0, removed_from_templates: templates?.n ?? 0 }
    await recordEvent(
      ctx,
      eventFor(actor, 'tags.delete', subjectOf(id), { name: tag.name, removed_from_certificates: result.removed_from_certificates, removed_from_templates: result.removed_from_templates }),
      tx,
    )
    return result
  })
}

export interface TagListRow {
  tag: TagRow
  certificate_count: number
  template_count: number
}

/**
 * Every tag alphabetically, with how many certificates and templates carry it. The list is kept
 * by admins and stays small, so it is not paged. Every role may read it.
 */
export async function listTags(ctx: Context, actor: Actor): Promise<TagListRow[]> {
  authorize(tagPolicy, actor, 'read', undefined)
  return tagRows(ctx.db)
}

/** One tag with its counts. */
export async function getTag(ctx: Context, actor: Actor, id: string): Promise<TagListRow> {
  authorize(tagPolicy, actor, 'read', undefined)
  const [row] = await tagRows(ctx.db, id)
  if (!row) throw new NotFoundError('Tag not found', 'tag_not_found')
  return row
}

function tagRows(db: Executor, id?: string): Promise<TagListRow[]> {
  const t = schema.tags
  return db
    .select({
      tag: t,
      certificate_count: sql<number>`(select count(*) from ${schema.certificateTags} where ${schema.certificateTags.tag_id} = ${t.id})`.mapWith(Number),
      template_count: sql<number>`(select count(*) from ${schema.templateTags} where ${schema.templateTags.tag_id} = ${t.id})`.mapWith(Number),
    })
    .from(t)
    .where(id ? eq(t.id, id) : undefined)
    .orderBy(sql`lower(${t.name})`, t.id)
}
