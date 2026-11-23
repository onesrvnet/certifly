import { jsonb, pgTable, text, timestamp } from 'drizzle-orm/pg-core'

/** Instance-wide settings as key/value pairs (base URL overrides, mail, CRL defaults, …). */
export const instanceSettings = pgTable('instance_settings', {
  key: text().primaryKey(),
  value: jsonb().$type<unknown>().notNull(),
  updated_at: timestamp({ withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
})
