import {
  type AnyPgColumn,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core'
import { sql } from 'drizzle-orm'
import { apiKeys } from './api-keys'
import { caCertificates, certificateAuthorities } from './cas'
import { bytea, id, timestamps } from './columns'
import { users } from './users'

export const templateStatus = pgEnum('template_status', ['active', 'archived'])

/** Subject attributes a template can default or let a requester set. */
export type SubjectField = 'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L' | 'E'
export type SanKind = 'dns' | 'ip' | 'email' | 'uri'
export type LeafKeyAlgorithm = 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096'
export type LeafKeyUsage = 'digital_signature' | 'non_repudiation' | 'key_encipherment' | 'data_encipherment' | 'key_agreement'
/** RFC 5280 §4.2.1.12 key purposes a template can set. */
export type LeafExtendedKeyUsage = 'server_auth' | 'client_auth' | 'code_signing' | 'email_protection' | 'time_stamping' | 'ocsp_signing'

/**
 * The rules for one kind of leaf certificate, bound to the CA that signs it. Every issuance path
 * (UI, API and later ACME and EST) goes through a template. Matching rules are domain patterns
 * (`api.example.com`, `*.svc.example.com`, `**.example.com`) and CIDRs, never regexes. Key usage
 * and extended key usage always come from here, never from a CSR. The slug may end up in protocol
 * URLs, so it never changes.
 */
export const templates = pgTable(
  'templates',
  {
    id: id(),
    slug: text().notNull().unique(),
    name: text().notNull(),
    description: text().notNull().default(''),
    ca_id: uuid()
      .notNull()
      .references(() => certificateAuthorities.id),
    status: templateStatus().notNull().default('active'),
    /** Which SAN types a request may carry. */
    allowed_san_types: text().array().$type<SanKind[]>().notNull(),
    /** Domain patterns for DNS SANs, and for the domain of email SANs and the host of URI SANs. */
    allowed_dns: jsonb().$type<string[]>().notNull().default([]),
    /** CIDRs for IP SANs. */
    allowed_ips: jsonb().$type<string[]>().notNull().default([]),
    allow_wildcards: boolean().notNull().default(false),
    require_san: boolean().notNull().default(true),
    require_common_name: boolean().notNull().default(false),
    /** Values for subject attributes the request does not set (or may not set). */
    subject_defaults: jsonb().$type<Partial<Record<SubjectField, string>>>().notNull().default({}),
    /** Subject attributes a requester may set; everything else comes from `subject_defaults`. */
    allowed_subject_fields: text().array().$type<SubjectField[]>().notNull(),
    /** Accepted leaf key algorithms, e.g. `ecdsa-p256`, `rsa-2048`. */
    key_algorithms: text().array().$type<LeafKeyAlgorithm[]>().notNull(),
    max_ttl_seconds: integer().notNull(),
    default_ttl_seconds: integer().notNull(),
    /** RSA-only usages (keyEncipherment, dataEncipherment) are left out for EC keys at issuance. */
    key_usages: text().array().$type<LeafKeyUsage[]>().notNull(),
    /** Never empty; validated in core. */
    extended_key_usages: text().array().$type<LeafExtendedKeyUsage[]>().notNull(),
    allow_server_keygen: boolean().notNull().default(false),
    allow_acme: boolean().notNull().default(false),
    allow_est: boolean().notNull().default(false),
    renew_before_days: integer().notNull(),
    archived_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [
    index('templates_ca_idx').on(t.ca_id),
    check('templates_ttl_check', sql`${t.default_ttl_seconds} > 0 and ${t.default_ttl_seconds} <= ${t.max_ttl_seconds}`),
  ],
)

export const certificateSource = pgEnum('certificate_source', ['ui', 'api', 'acme', 'est', 'import'])
/**
 * Stored states. `expired` is derived on read from `not_after` for active certificates, so the
 * column only changes on revoke and renew; the value exists for imported inventory.
 */
export const certificateStatus = pgEnum('certificate_status', ['active', 'revoked', 'expired', 'superseded'])

/** A SAN as stored: normalised by pki. */
export interface StoredSan {
  type: SanKind
  value: string
}

/**
 * A leaf certificate certifly issued, or one issued elsewhere and imported into the inventory
 * (`source = import`, no CA, the issuer's DN only). The DER is the source of truth; the other
 * columns are copies for listing and filtering. Leaf private keys are never stored: a key
 * generated for a request is returned once and dropped. Serials are unique per issuing CA.
 */
export const certificates = pgTable(
  'certificates',
  {
    id: id(),
    /** Null for imported certificates. */
    ca_id: uuid().references(() => certificateAuthorities.id),
    /** The CA certificate version (and so the key) that signed it; null for imported certificates. */
    ca_cert_id: uuid().references(() => caCertificates.id),
    template_id: uuid().references(() => templates.id),
    source: certificateSource().notNull(),
    status: certificateStatus().notNull().default('active'),
    /** Lowercase hex as encoded in the certificate. */
    serial: text().notNull(),
    subject_dn: text().notNull(),
    issuer_dn: text().notNull(),
    common_name: text(),
    sans: jsonb().$type<StoredSan[]>().notNull().default([]),
    key_algorithm: text().notNull(),
    key_usages: text().array().$type<LeafKeyUsage[]>().notNull(),
    extended_key_usages: text().array().$type<LeafExtendedKeyUsage[]>().notNull(),
    not_before: timestamp({ withTimezone: true }).notNull(),
    not_after: timestamp({ withTimezone: true }).notNull(),
    fingerprint_sha256: text().notNull(),
    certificate_der: bytea().notNull(),
    /** The verified request, kept so a renewal can reuse it. Null when certifly generated the key. */
    csr_pem: text(),
    /** certifly generated the key pair and handed out the private key once. */
    key_generated: boolean().notNull().default(false),
    revoked_at: timestamp({ withTimezone: true }),
    /** RFC 5280 CRLReason code. */
    revocation_reason: integer(),
    superseded_by_id: uuid().references((): AnyPgColumn => certificates.id),
    requested_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    requested_by_api_key_id: uuid().references(() => apiKeys.id, { onDelete: 'set null' }),
    labels: jsonb().$type<Record<string, string>>().notNull().default({}),
    notes: text().notNull().default(''),
    ...timestamps,
  },
  (t) => [
    uniqueIndex('certificates_ca_serial_idx').on(t.ca_id, t.serial),
    uniqueIndex('certificates_fingerprint_idx').on(t.fingerprint_sha256),
    index('certificates_created_idx').on(t.created_at, t.id),
    index('certificates_not_after_idx').on(t.not_after, t.id),
    index('certificates_template_idx').on(t.template_id),
    index('certificates_status_idx').on(t.status),
    index('certificates_superseded_by_idx').on(t.superseded_by_id),
    index('certificates_ca_cert_idx').on(t.ca_cert_id),
    check('certificates_import_check', sql`(${t.source} = 'import') = (${t.ca_id} is null)`),
    check('certificates_ca_cert_check', sql`(${t.ca_id} is null) = (${t.ca_cert_id} is null)`),
  ],
)
