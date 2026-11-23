import { type Executor, schema, type Transaction } from '@certifly/db'
import { and, eq, gte, lte, type SQL } from 'drizzle-orm'
import type { Context } from './context'
import { type CursorInput, keyset, paged } from './cursor'
import { authorize, auditPolicy, type Actor } from './policies'

export type ActorType = (typeof schema.actorType.enumValues)[number]
export type EventRow = typeof schema.events.$inferSelect

/** An audit entry about to be stored. Ids and short facts only: never secrets or key material. */
export interface NewEvent {
  actor_type: ActorType
  actor_id?: string | null
  /** Dotted name such as `users.update_role`. */
  name: string
  subject_type?: string | null
  subject_id?: string | null
  data?: Record<string, unknown>
  ip?: string | null
}

/** Called after an event has been stored. */
export type EmitEvent = (event: EventRow) => void

/** The event for something an actor did: sessions count as users, API keys as the key. */
export function eventFor(
  actor: Actor,
  name: string,
  subject?: { type: string; id: string },
  data: Record<string, unknown> = {},
): NewEvent {
  const by_key = actor.kind === 'api_key'
  const by_cli = actor.kind === 'cli'
  return {
    actor_type: by_key ? 'api_key' : by_cli ? 'cli' : 'user',
    actor_id: by_key ? (actor.api_key_id ?? actor.id) : by_cli ? (actor.cli_session_id ?? actor.id) : actor.id,
    name,
    subject_type: subject?.type ?? null,
    subject_id: subject?.id ?? null,
    // A key or command-line session acts as its owner; keep who that was.
    data: by_key || by_cli ? { ...data, user_id: actor.id } : data,
    ip: actor.ip ?? null,
  }
}

/** The event for something certifly did by itself, such as a scheduled cleanup. */
export function systemEvent(name: string, subject?: { type: string; id: string }, data: Record<string, unknown> = {}): NewEvent {
  return { actor_type: 'system', name, subject_type: subject?.type ?? null, subject_id: subject?.id ?? null, data }
}

/** Events recorded inside an open `withTransaction`, told to subscribers once it commits. */
const pendingEvents = new WeakMap<Executor, EventRow[]>()

function emitSafely(ctx: Context, row: EventRow) {
  // Subscribers must not break the change that was already stored.
  try {
    ctx.emit(row)
  } catch (error) {
    console.error('[audit] event subscriber failed', error)
  }
}

/**
 * Run `fn` in a database transaction. Audit events it records are told to subscribers only
 * after the commit, so an alert never fires for a change that was rolled back.
 */
export async function withTransaction<T>(ctx: Context, fn: (tx: Transaction) => Promise<T>): Promise<T> {
  const pending: EventRow[] = []
  const result = await ctx.db.transaction(async (tx) => {
    pendingEvents.set(tx, pending)
    return fn(tx)
  })
  for (const row of pending) emitSafely(ctx, row)
  return result
}

/**
 * Append an entry to the audit log. Pass the transaction of `withTransaction` to make the
 * entry commit or roll back with the change it describes. There is no function that updates
 * or deletes entries; the log only grows.
 */
export async function recordEvent(ctx: Context, event: NewEvent, db: Executor = ctx.db): Promise<EventRow> {
  const pending = db === ctx.db ? null : pendingEvents.get(db)
  if (pending === undefined) throw new Error('recordEvent: open transactions with withTransaction')
  const [row] = await db
    .insert(schema.events)
    .values({
      actor_type: event.actor_type,
      actor_id: event.actor_id ?? null,
      name: event.name,
      subject_type: event.subject_type ?? null,
      subject_id: event.subject_id ?? null,
      data: event.data ?? {},
      ip: event.ip ?? null,
    })
    .returning()
  if (pending) pending.push(row!)
  else emitSafely(ctx, row!)
  return row!
}

export interface ListEventsInput extends CursorInput {
  actor_id?: string
  actor_type?: ActorType
  /** Exact event name. */
  name?: string
  subject_type?: string
  subject_id?: string
  from?: Date
  to?: Date
}

/** The audit log, newest first, with the name of the user behind each entry where there is one. */
export async function listEvents(ctx: Context, actor: Actor, input: ListEventsInput) {
  authorize(auditPolicy, actor, 'read', undefined)
  const filters: (SQL | undefined)[] = []
  if (input.actor_id) filters.push(eq(schema.events.actor_id, input.actor_id))
  if (input.actor_type) filters.push(eq(schema.events.actor_type, input.actor_type))
  if (input.name) filters.push(eq(schema.events.name, input.name))
  if (input.subject_type) filters.push(eq(schema.events.subject_type, input.subject_type))
  if (input.subject_id) filters.push(eq(schema.events.subject_id, input.subject_id))
  if (input.from) filters.push(gte(schema.events.created_at, input.from))
  if (input.to) filters.push(lte(schema.events.created_at, input.to))

  const page = keyset(
    [
      { expr: schema.events.created_at, type: 'timestamptz', direction: 'desc' },
      { expr: schema.events.id, type: 'uuid', direction: 'desc' },
    ],
    input,
  )
  const rows = await ctx.db
    .select({
      cursor_keys: page.keys,
      event: schema.events,
      actor_name: schema.users.name,
    })
    .from(schema.events)
    .leftJoin(schema.users, and(eq(schema.users.id, schema.events.actor_id), eq(schema.events.actor_type, 'user')))
    .where(and(...filters, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  return paged(rows, input.limit)
}
