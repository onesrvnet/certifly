import { index, jsonb, pgEnum, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core'
import { id } from './columns'

export const actorType = pgEnum('actor_type', ['user', 'api_key', 'acme', 'est', 'system', 'cli', 'ssh_host'])

/**
 * The audit log: who did what to which thing. Append-only: core has no function that
 * updates or deletes a row. Actor and subject ids carry no foreign keys, so entries outlive what they
 * describe. `data` holds ids and short facts, never secrets or key material.
 */
export const events = pgTable(
  'events',
  {
    id: id(),
    actor_type: actorType().notNull(),
    /** The user, API key or protocol account; null for the system itself. */
    actor_id: uuid(),
    /** Dotted name such as `users.update_role`. */
    name: text().notNull(),
    subject_type: text(),
    subject_id: uuid(),
    data: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    ip: text(),
    created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('events_created_idx').on(t.created_at, t.id),
    index('events_actor_created_idx').on(t.actor_id, t.created_at),
    index('events_name_created_idx').on(t.name, t.created_at),
    index('events_subject_created_idx').on(t.subject_type, t.subject_id, t.created_at),
  ],
)
