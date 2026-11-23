import { integer, pgTable, primaryKey, text, timestamp } from 'drizzle-orm/pg-core'

/**
 * Fixed-window request counters, one row per key and window. They are disposable: the
 * cleanup job deletes windows older than a day, so a window must not be longer than that.
 */
export const rateLimits = pgTable(
  'rate_limits',
  {
    key: text().notNull(),
    window_start: timestamp({ withTimezone: true }).notNull(),
    count: integer().notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.key, t.window_start] })],
)
