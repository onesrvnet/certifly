import { sql } from 'drizzle-orm'
import {
  type AnyPgColumn,
  bigint,
  check,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core'
import { bytea, id, timestamps } from './columns'
import { users } from './users'

/** How a CA's certificate comes about: self-signed root, signed by a parent CA in certifly, or signed outside. */
export const caSigning = pgEnum('ca_signing', ['self_signed', 'internal', 'external'])
export const caStatus = pgEnum('ca_status', ['pending_certificate', 'active', 'disabled', 'expired'])
/** Where a CA key lives. Only keys encrypted under the master key for now; HSM/KMS providers can follow. */
export const keySource = pgEnum('key_source', ['local'])

/** Name constraints as certifly stores them: normalised DNS suffixes, CIDRs and email forms. */
export interface StoredNameConstraints {
  permitted: { dns: string[]; ip: string[]; email: string[] }
  excluded: { dns: string[]; ip: string[]; email: string[] }
}

/**
 * A certificate authority. The slug is part of the public CRL and certificate URLs that get
 * embedded in issued certificates, so it never changes. Certificates (`ca_certificates`) and
 * keys (`ca_keys`) are versioned; `active_cert_id` and `active_key_id` point at the ones in use.
 */
export const certificateAuthorities = pgTable(
  'certificate_authorities',
  {
    id: id(),
    slug: text().notNull().unique(),
    name: text().notNull(),
    description: text().notNull().default(''),
    signing: caSigning().notNull(),
    /** Set exactly for internal CAs. */
    parent_ca_id: uuid().references((): AnyPgColumn => certificateAuthorities.id),
    status: caStatus().notNull(),
    subject_dn: text().notNull(),
    key_algorithm: text().notNull(),
    /** null for unlimited. */
    max_path_length: integer(),
    name_constraints: jsonb().$type<StoredNameConstraints | null>(),
    active_cert_id: uuid().references((): AnyPgColumn => caCertificates.id),
    active_key_id: uuid().references((): AnyPgColumn => caKeys.id),
    crl_validity_hours: integer().notNull(),
    crl_overlap_hours: integer().notNull(),
    not_before: timestamp({ withTimezone: true }),
    not_after: timestamp({ withTimezone: true }),
    disabled_at: timestamp({ withTimezone: true }),
    /**
     * When the CA was revoked: on its parent's CRL for an internal CA, or marked compromised for
     * an externally signed one (its revocation then happens at the outside issuer).
     */
    revoked_at: timestamp({ withTimezone: true }),
    /** RFC 5280 CRLReason code. */
    revocation_reason: integer(),
    ...timestamps,
  },
  (t) => [
    index('certificate_authorities_parent_idx').on(t.parent_ca_id),
    check('certificate_authorities_parent_check', sql`(${t.signing} = 'internal') = (${t.parent_ca_id} is not null)`),
    check('certificate_authorities_crl_hours_check', sql`${t.crl_overlap_hours} >= 0 and ${t.crl_overlap_hours} < ${t.crl_validity_hours}`),
  ],
)

/**
 * A CA private key, encrypted with envelope encryption by the keyvault and bound to
 * `ca_key:<ca_id>:<key_id>`, so a record copied to another row does not decrypt. The columns
 * are the keyvault's EncryptedKeyRecord.
 */
export const caKeys = pgTable(
  'ca_keys',
  {
    id: id(),
    ca_id: uuid()
      .notNull()
      .references((): AnyPgColumn => certificateAuthorities.id),
    key_source: keySource().notNull().default('local'),
    algorithm: text().notNull(),
    public_key_spki: bytea().notNull(),
    alg: text().notNull(),
    /** Which master key wrapped the DEK; records under an older one are re-wrapped by a job. */
    kek_id: text().notNull(),
    wrapped_dek: bytea().notNull(),
    dek_iv: bytea().notNull(),
    dek_tag: bytea().notNull(),
    ciphertext: bytea().notNull(),
    iv: bytea().notNull(),
    tag: bytea().notNull(),
    ...timestamps,
  },
  (t) => [index('ca_keys_ca_idx').on(t.ca_id), index('ca_keys_kek_idx').on(t.kek_id)],
)

/**
 * One installed certificate of a CA: the first one and every renewal or re-import. Old versions
 * stay so that chains and CRLs they signed can still be verified. `issuer_ca_id` is the certifly
 * CA that signed it (the CA itself for a root, null when signed outside); serials are unique per
 * issuer, and a parent's CRL lists the revoked ones it issued.
 */
export const caCertificates = pgTable(
  'ca_certificates',
  {
    id: id(),
    ca_id: uuid()
      .notNull()
      .references((): AnyPgColumn => certificateAuthorities.id),
    key_id: uuid()
      .notNull()
      .references(() => caKeys.id),
    issuer_ca_id: uuid().references((): AnyPgColumn => certificateAuthorities.id),
    /** The issuer's key that signed it, which decides the CRL it is listed on; null when signed outside. */
    issuer_key_id: uuid().references(() => caKeys.id),
    version: integer().notNull(),
    certificate_der: bytea().notNull(),
    /** Issuer first, root last; excludes the certificate itself. Empty for a root. */
    chain_pem: text().notNull(),
    /** Lowercase hex as encoded in the certificate. */
    serial: text().notNull(),
    issuer_dn: text().notNull(),
    not_before: timestamp({ withTimezone: true }).notNull(),
    not_after: timestamp({ withTimezone: true }).notNull(),
    fingerprint_sha256: text().notNull(),
    revoked_at: timestamp({ withTimezone: true }),
    /** RFC 5280 CRLReason code. */
    revocation_reason: integer(),
    ...timestamps,
  },
  (t) => [
    uniqueIndex('ca_certificates_version_idx').on(t.ca_id, t.version),
    uniqueIndex('ca_certificates_issuer_serial_idx').on(t.issuer_ca_id, t.serial),
    uniqueIndex('ca_certificates_fingerprint_idx').on(t.ca_id, t.fingerprint_sha256),
  ],
)

/** A certificate request for an externally signed CA, waiting for (or used by) an import. */
export const caCsrs = pgTable(
  'ca_csrs',
  {
    id: id(),
    ca_id: uuid()
      .notNull()
      .references(() => certificateAuthorities.id),
    key_id: uuid()
      .notNull()
      .references(() => caKeys.id),
    csr_pem: text().notNull(),
    /** null for unlimited. */
    requested_path_length: integer(),
    created_by_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    /** When a certificate for this request was imported. */
    consumed_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index('ca_csrs_ca_created_idx').on(t.ca_id, t.created_at)],
)

/**
 * The current CRL of each CA key. Every key that signed certificates still valid keeps its own
 * CRL, signed by that key, so certificates issued before a new-key renewal can still be checked.
 * The number grows across all of a CA's CRLs (RFC 5280 §5.2.3).
 */
export const crls = pgTable(
  'crls',
  {
    ca_id: uuid()
      .notNull()
      .references(() => certificateAuthorities.id),
    key_id: uuid()
      .notNull()
      .references(() => caKeys.id),
    crl_number: bigint({ mode: 'bigint' }).notNull(),
    this_update: timestamp({ withTimezone: true }).notNull(),
    next_update: timestamp({ withTimezone: true }).notNull(),
    crl_der: bytea().notNull(),
    ...timestamps,
  },
  (t) => [primaryKey({ columns: [t.ca_id, t.key_id] }), index('crls_next_update_idx').on(t.next_update)],
)
