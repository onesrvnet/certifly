import { index, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core'
import { id, timestamps } from './columns'
import { users } from './users'

/** Personal API token acting as its user. Only a hash is stored. */
export const apiKeys = pgTable(
  'api_keys',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text().notNull(),
    /** SHA-256 of the secret. */
    secret_hash: text().notNull().unique(),
    /** Last characters of the secret, shown to help users recognise a key. */
    last4: text().notNull(),
    expires_at: timestamp({ withTimezone: true }),
    last_used_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index('api_keys_user_idx').on(t.user_id)],
)
