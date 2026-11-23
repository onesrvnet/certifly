import { sql } from 'drizzle-orm'
import { bigint, index, integer, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core'
import { bytea, id, timestamps } from './columns'
import { userRole, users } from './users'

/** Single-use email credentials, stored hashed: a link token and a short numeric code to sign in. */
export const emailTokens = pgTable(
  'email_tokens',
  {
    id: id(),
    email: text().notNull(),
    token_hash: text().notNull().unique(),
    /** HMAC of the code with the server's secret key, bound to this token's id. */
    code_hash: text().notNull(),
    /** Code attempts so far; the token is burned after too many. */
    attempts: integer().notNull().default(0),
    /** Extra data carried through sign-in: `setup_proven` when the setup token was shown on request. */
    meta: jsonb().$type<{ setup_proven?: boolean }>().notNull().default({}),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    consumed_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index('email_tokens_email_idx').on(t.email, t.created_at)],
)

/** Link between a user and an external identity (e.g. an OIDC subject). */
export const userIdentities = pgTable(
  'user_identities',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: text().notNull(),
    provider_user_id: text().notNull(),
    ...timestamps,
  },
  (t) => [uniqueIndex('user_identities_provider_subject_idx').on(t.provider, t.provider_user_id)],
)

/** WebAuthn credentials (passkeys) a user signs in with. */
export const passkeys = pgTable(
  'passkeys',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** Credential id as base64url, as browsers report it. */
    credential_id: text().notNull().unique(),
    public_key: bytea().notNull(),
    /** Signature counter, an unsigned 32-bit number; a lower value than stored means a cloned authenticator. */
    counter: bigint({ mode: 'number' }).notNull().default(0),
    transports: jsonb().$type<string[]>().notNull().default([]),
    /** Shown in settings, e.g. "MacBook" or the authenticator's name. */
    name: text().notNull(),
    last_used_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index('passkeys_user_idx').on(t.user_id)],
)

/** An admin's invitation for an email address to join with a role. Only a hash of the link token is stored. */
export const invites = pgTable(
  'invites',
  {
    id: id(),
    email: text().notNull(),
    role: userRole().notNull().default('viewer'),
    invited_by_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    token_hash: text().notNull().unique(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    accepted_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [
    index('invites_email_idx').on(t.email),
    // One pending invite per address: a new one replaces the old.
    uniqueIndex('invites_pending_email_idx').on(t.email).where(sql`${t.accepted_at} is null`),
  ],
)
