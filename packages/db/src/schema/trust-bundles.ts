import { boolean, index, integer, pgTable, primaryKey, text, uuid } from 'drizzle-orm/pg-core'
import { certificateAuthorities } from './cas'
import { id, timestamps } from './columns'

/**
 * A named set of CA certificates for client trust stores and mTLS `ca_file` settings, served
 * publicly as PEM. The slug is part of that public URL, so it never changes.
 */
export const trustBundles = pgTable('trust_bundles', {
  id: id(),
  slug: text().notNull().unique(),
  name: text().notNull(),
  description: text().notNull().default(''),
  /** Also add each chosen CA's issuer chain up to the root. */
  include_chain: boolean().notNull().default(false),
  /** Also serve the bundle as Traefik dynamic configuration (HTTP provider). */
  traefik_enabled: boolean().notNull().default(false),
  /** Emit a TLS option that makes Traefik verify client certificates against the bundle. */
  traefik_client_auth: boolean().notNull().default(true),
  /** Traefik's `clientAuthType` for that option. */
  traefik_client_auth_type: text().notNull().default('RequireAndVerifyClientCert'),
  /** Name of the TLS option; null means `<slug>-mtls`. */
  traefik_tls_option_name: text(),
  /** Emit a servers transport that trusts backends signed by the bundle. */
  traefik_servers_transport: boolean().notNull().default(true),
  /** Name of the servers transport; null means the slug. */
  traefik_servers_transport_name: text(),
  /** Require the bundle's own token (`Authorization: Bearer tb_…`) to fetch the Traefik configuration. */
  traefik_require_token: boolean().notNull().default(false),
  /** SHA-256 of that token; the token itself is shown once and never stored. Null when no token is required. */
  traefik_token_hash: text(),
  ...timestamps,
})

/** The CAs in a bundle, in the order the admin picked them. */
export const trustBundleCas = pgTable(
  'trust_bundle_cas',
  {
    bundle_id: uuid()
      .notNull()
      .references(() => trustBundles.id, { onDelete: 'cascade' }),
    ca_id: uuid()
      .notNull()
      .references(() => certificateAuthorities.id),
    position: integer().notNull(),
  },
  (t) => [primaryKey({ columns: [t.bundle_id, t.ca_id] }), index('trust_bundle_cas_ca_idx').on(t.ca_id)],
)
