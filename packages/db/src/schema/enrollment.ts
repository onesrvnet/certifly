import { index, jsonb, pgEnum, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core'
import { certificates, templates } from './certificates'
import { id, timestamps } from './columns'
import { users } from './users'

/*
 * Automated enrollment: ACME (RFC 8555) and EST (RFC 7030), both per template. The template's
 * rules apply to everything issued this way.
 */

/**
 * External account binding keys for a template's ACME directory. A new ACME account must be
 * bound to one; revoking the key stops new accounts and orders through accounts bound to it.
 */
export const acmeEabKeys = pgTable(
  'acme_eab_keys',
  {
    id: id(),
    template_id: uuid()
      .notNull()
      .references(() => templates.id, { onDelete: 'cascade' }),
    name: text().notNull(),
    /** The key identifier clients send as `kid`. */
    kid: text().notNull().unique(),
    /** The HMAC key, encrypted with `encryptSecret`: verifying the binding needs the key itself. */
    hmac_key_encrypted: text().notNull(),
    created_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    last_used_at: timestamp({ withTimezone: true }),
    revoked_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index('acme_eab_keys_template_idx').on(t.template_id)],
)

export const acmeAccountStatus = pgEnum('acme_account_status', ['valid', 'deactivated', 'revoked'])

export const acmeAccounts = pgTable(
  'acme_accounts',
  {
    id: id(),
    template_id: uuid()
      .notNull()
      .references(() => templates.id, { onDelete: 'cascade' }),
    eab_key_id: uuid()
      .notNull()
      .references(() => acmeEabKeys.id, { onDelete: 'cascade' }),
    /** RFC 7638 thumbprint of the account key, base64url. One account per key and template. */
    jwk_thumbprint: text().notNull(),
    jwk: jsonb().$type<Record<string, unknown>>().notNull(),
    contact: jsonb().$type<string[]>().notNull().default([]),
    status: acmeAccountStatus().notNull().default('valid'),
    ...timestamps,
  },
  (t) => [index('acme_accounts_template_idx').on(t.template_id), index('acme_accounts_thumbprint_idx').on(t.template_id, t.jwk_thumbprint)],
)

export const acmeOrderStatus = pgEnum('acme_order_status', ['pending', 'ready', 'processing', 'valid', 'invalid'])

export interface AcmeIdentifier {
  type: 'dns' | 'ip'
  value: string
}

export const acmeOrders = pgTable(
  'acme_orders',
  {
    id: id(),
    account_id: uuid()
      .notNull()
      .references(() => acmeAccounts.id, { onDelete: 'cascade' }),
    status: acmeOrderStatus().notNull().default('pending'),
    identifiers: jsonb().$type<AcmeIdentifier[]>().notNull(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    certificate_id: uuid().references(() => certificates.id, { onDelete: 'set null' }),
    /** RFC 7807 problem document when the order became invalid. */
    error: jsonb().$type<Record<string, unknown> | null>(),
    ...timestamps,
  },
  (t) => [index('acme_orders_account_idx').on(t.account_id)],
)

export const acmeAuthorizationStatus = pgEnum('acme_authorization_status', ['pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked'])

export const acmeAuthorizations = pgTable(
  'acme_authorizations',
  {
    id: id(),
    order_id: uuid()
      .notNull()
      .references(() => acmeOrders.id, { onDelete: 'cascade' }),
    identifier: jsonb().$type<AcmeIdentifier>().notNull(),
    status: acmeAuthorizationStatus().notNull().default('pending'),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    ...timestamps,
  },
  (t) => [index('acme_authorizations_order_idx').on(t.order_id)],
)

export const acmeChallengeType = pgEnum('acme_challenge_type', ['http-01', 'tls-alpn-01'])
export const acmeChallengeStatus = pgEnum('acme_challenge_status', ['pending', 'processing', 'valid', 'invalid'])

export const acmeChallenges = pgTable(
  'acme_challenges',
  {
    id: id(),
    authorization_id: uuid()
      .notNull()
      .references(() => acmeAuthorizations.id, { onDelete: 'cascade' }),
    type: acmeChallengeType().notNull(),
    token: text().notNull(),
    status: acmeChallengeStatus().notNull().default('pending'),
    validated_at: timestamp({ withTimezone: true }),
    error: jsonb().$type<Record<string, unknown> | null>(),
    ...timestamps,
  },
  (t) => [index('acme_challenges_authorization_idx').on(t.authorization_id)],
)

/** Replay nonces handed out by `newNonce` and in every ACME response; each is accepted once. */
export const acmeNonces = pgTable(
  'acme_nonces',
  {
    nonce: text().primaryKey(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
  },
  (t) => [index('acme_nonces_expires_idx').on(t.expires_at)],
)

/** HTTP basic credentials for a template's EST endpoints. Only a hash of the password is stored. */
export const estCredentials = pgTable(
  'est_credentials',
  {
    id: id(),
    template_id: uuid()
      .notNull()
      .references(() => templates.id, { onDelete: 'cascade' }),
    name: text().notNull(),
    username: text().notNull().unique(),
    /** SHA-256 of the generated password (high entropy, so no slow hash is needed). */
    password_hash: text().notNull(),
    created_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    last_used_at: timestamp({ withTimezone: true }),
    revoked_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index('est_credentials_template_idx').on(t.template_id)],
)
