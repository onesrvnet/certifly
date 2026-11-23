import { sql } from 'drizzle-orm'
import { index, jsonb, pgEnum, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core'
import { id, timestamps } from './columns'

export const userRole = pgEnum('user_role', ['admin', 'operator', 'viewer'])

export const users = pgTable(
  'users',
  {
    id: id(),
    /** Stored lowercased; core normalises it before every lookup and write, and the index holds whatever slips past. */
    email: text().notNull(),
    name: text().notNull(),
    /** The person's SSH username, used in `<host group>:<username>` principals. Set on first use from the email, unique whatever the case. */
    username: text(),
    role: userRole().notNull().default('viewer'),
    preferences: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    last_active_at: timestamp({ withTimezone: true }),
    last_signed_in_at: timestamp({ withTimezone: true }),
    ...timestamps,
    /** Deactivated: cannot sign in, but the row stays so audit entries keep a name. */
    deleted_at: timestamp({ withTimezone: true }),
  },
  // Unique whatever the case, so `Ann@…` and `ann@…` can never be two accounts.
  (t) => [uniqueIndex('users_email_lower_idx').on(sql`lower(${t.email})`), uniqueIndex('users_username_lower_idx').on(sql`lower(${t.username})`)],
)

export const sessions = pgTable(
  'sessions',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    user_agent: text(),
    ip_address: text(),
    /** When the person last proved who they are in this session; sensitive actions need it to be recent. */
    reauth_at: timestamp({ withTimezone: true }),
    last_active_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    ...timestamps,
  },
  (t) => [index('sessions_user_idx').on(t.user_id)],
)
