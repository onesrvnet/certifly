import { sql } from 'drizzle-orm'
import { bigint, boolean, index, integer, pgEnum, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core'
import { bytea, id, timestamps } from './columns'
import { users } from './users'

/*
 * SSH certificate authorities, host groups, hosts and the certificates certifly signs for
 * them. One SSH CA key signs both user and host certificates. certifly only ever signs public
 * keys; private keys of users and hosts never reach it.
 */

export const sshCaSource = pgEnum('ssh_ca_source', ['generated', 'imported'])
export const sshKeyPolicy = pgEnum('ssh_key_policy', ['any', 'sk', 'sk_attested'])
export const sshCertificateKind = pgEnum('ssh_certificate_kind', ['user', 'host'])
export const cliLoginStatus = pgEnum('cli_login_status', ['pending', 'approved', 'denied'])
export const groupMemberSource = pgEnum('group_member_source', ['manual', 'oidc'])

export const sshCas = pgTable('ssh_cas', {
  id: id(),
  /** Part of the public `.pub` and `.krl` URLs, so it never changes. */
  slug: text().notNull().unique(),
  name: text().notNull(),
  description: text().notNull().default(''),
  /** `ed25519`, `ecdsa-p256` or `rsa-4096`. */
  key_algorithm: text().notNull(),
  source: sshCaSource().notNull(),
  /** The CA public key as an authorized_keys line. */
  public_key: text().notNull(),
  fingerprint: text().notNull(),
  ...timestamps,
})

/**
 * The CA's private key, encrypted by the keyvault and bound to `ssh_ca_key:<ca_id>:<key_id>`.
 * The columns are the keyvault's EncryptedKeyRecord.
 */
export const sshCaKeys = pgTable(
  'ssh_ca_keys',
  {
    id: id(),
    ssh_ca_id: uuid()
      .notNull()
      .references(() => sshCas.id, { onDelete: 'cascade' }),
    algorithm: text().notNull(),
    public_key_spki: bytea().notNull(),
    alg: text().notNull(),
    kek_id: text().notNull(),
    wrapped_dek: bytea().notNull(),
    dek_iv: bytea().notNull(),
    dek_tag: bytea().notNull(),
    ciphertext: bytea().notNull(),
    iv: bytea().notNull(),
    tag: bytea().notNull(),
    ...timestamps,
  },
  (t) => [uniqueIndex('ssh_ca_keys_ca_idx').on(t.ssh_ca_id), index('ssh_ca_keys_kek_idx').on(t.kek_id)],
)

/** Rules and defaults for a set of hosts. The slug is the first part of every principal (`prod:root`). */
export const sshHostGroups = pgTable(
  'ssh_host_groups',
  {
    id: id(),
    slug: text().notNull().unique(),
    name: text().notNull(),
    description: text().notNull().default(''),
    ssh_ca_id: uuid()
      .notNull()
      .references(() => sshCas.id),
    /** Domain patterns a host's names must match, e.g. `*.prod.corp`. */
    host_patterns: text().array().notNull().default([]),
    user_ttl_default_seconds: integer().notNull(),
    user_ttl_max_seconds: integer().notNull(),
    /** OpenSSH extension names, e.g. `permit-pty`. */
    user_extensions: text().array().notNull().default([]),
    force_command: text(),
    /** Addresses and CIDRs for the `source-address` critical option. */
    source_address: text().array().notNull().default([]),
    key_policy: sshKeyPolicy().notNull().default('any'),
    host_ttl_seconds: integer().notNull(),
    ...timestamps,
  },
  (t) => [index('ssh_host_groups_ca_idx').on(t.ssh_ca_id)],
)

/** Groups of people, managed in certifly; provider group names map members in at OIDC sign-in. */
export const groups = pgTable(
  'groups',
  {
    id: id(),
    name: text().notNull(),
    description: text().notNull().default(''),
    /** Group names at the identity provider whose members belong to this group. */
    provider_groups: text().array().notNull().default([]),
    ...timestamps,
  },
  (t) => [uniqueIndex('groups_name_lower_idx').on(sql`lower(${t.name})`)],
)

export const groupMembers = pgTable(
  'group_members',
  {
    group_id: uuid()
      .notNull()
      .references(() => groups.id, { onDelete: 'cascade' }),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** `oidc` rows follow the provider's groups at each sign-in; `manual` rows are never touched by it, and adding a person by hand turns their `oidc` row into a `manual` one. */
    source: groupMemberSource().notNull().default('manual'),
    created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.group_id, t.user_id] }), index('group_members_user_idx').on(t.user_id)],
)

/** Which group may log in to a host group as whom. */
export const sshAccessRules = pgTable(
  'ssh_access_rules',
  {
    id: id(),
    host_group_id: uuid()
      .notNull()
      .references(() => sshHostGroups.id, { onDelete: 'cascade' }),
    group_id: uuid()
      .notNull()
      .references(() => groups.id, { onDelete: 'cascade' }),
    /** Fixed local login names. */
    logins: text().array().notNull().default([]),
    /** Members may also log in as their own username. */
    own_username: boolean().notNull().default(false),
    ...timestamps,
  },
  (t) => [uniqueIndex('ssh_access_rules_pair_idx').on(t.host_group_id, t.group_id), index('ssh_access_rules_group_idx').on(t.group_id)],
)

export const sshHosts = pgTable(
  'ssh_hosts',
  {
    id: id(),
    name: text().notNull(),
    host_group_id: uuid()
      .notNull()
      .references(() => sshHostGroups.id),
    hostnames: text().array().notNull(),
    /** Host public keys as `<type> <base64>` lines. */
    public_keys: text().array().notNull(),
    last_seen_at: timestamp({ withTimezone: true }),
    created_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    ...timestamps,
  },
  (t) => [index('ssh_hosts_group_idx').on(t.host_group_id), uniqueIndex('ssh_hosts_name_lower_idx').on(sql`lower(${t.name})`)],
)

/** Single-use enrollment secrets for hosts. Only a hash is stored. */
export const sshJoinTokens = pgTable(
  'ssh_join_tokens',
  {
    id: id(),
    host_group_id: uuid()
      .notNull()
      .references(() => sshHostGroups.id, { onDelete: 'cascade' }),
    label: text().notNull().default(''),
    token_hash: text().notNull().unique(),
    last4: text().notNull(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    used_at: timestamp({ withTimezone: true }),
    host_id: uuid().references(() => sshHosts.id, { onDelete: 'set null' }),
    created_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    ...timestamps,
  },
  (t) => [index('ssh_join_tokens_group_idx').on(t.host_group_id)],
)

/** A nonce a host signs to prove it holds one of its registered keys. Single use, five minutes. */
export const sshHostChallenges = pgTable(
  'ssh_host_challenges',
  {
    id: id(),
    host_id: uuid()
      .notNull()
      .references(() => sshHosts.id, { onDelete: 'cascade' }),
    nonce_hash: text().notNull().unique(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    used_at: timestamp({ withTimezone: true }),
    created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('ssh_host_challenges_host_idx').on(t.host_id)],
)

/** User and host certificates certifly has signed. The certificate line is the source of truth. */
export const sshCertificates = pgTable(
  'ssh_certificates',
  {
    id: id(),
    ssh_ca_id: uuid()
      .notNull()
      .references(() => sshCas.id),
    kind: sshCertificateKind().notNull(),
    /** Random, 63 bits, unique per CA. */
    serial: bigint({ mode: 'bigint' }).notNull(),
    key_id: text().notNull(),
    principals: text().array().notNull(),
    /** The certified public key, as `<type> <base64>`. */
    public_key: text().notNull(),
    fingerprint: text().notNull(),
    certificate: text().notNull(),
    valid_after: timestamp({ withTimezone: true }).notNull(),
    valid_before: timestamp({ withTimezone: true }).notNull(),
    host_group_id: uuid().references(() => sshHostGroups.id, { onDelete: 'set null' }),
    /** The person a user certificate is for. */
    user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    /** Who asked for it, when that is someone else (an operator signing for a person). */
    requested_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    host_id: uuid().references(() => sshHosts.id, { onDelete: 'set null' }),
    /**
     * The machine whose CLI asked for a user certificate (its host name); null when signed on the
     * web or with an API key. A newer certificate from the same machine supersedes the older one.
     */
    machine: text(),
    /** The key was proven to be a genuine hardware key at signing time. */
    attested: boolean().notNull().default(false),
    revoked_at: timestamp({ withTimezone: true }),
    revocation_reason: text(),
    ...timestamps,
  },
  (t) => [
    uniqueIndex('ssh_certificates_serial_idx').on(t.ssh_ca_id, t.serial),
    index('ssh_certificates_user_idx').on(t.user_id, t.created_at),
    index('ssh_certificates_host_idx').on(t.host_id, t.created_at),
    index('ssh_certificates_group_idx').on(t.host_group_id),
    index('ssh_certificates_created_idx').on(t.created_at, t.id),
  ],
)

/** The binary OpenSSH revocation list of one SSH CA, rebuilt with every revocation. */
export const sshKrls = pgTable('ssh_krls', {
  ssh_ca_id: uuid()
    .primaryKey()
    .references(() => sshCas.id, { onDelete: 'cascade' }),
  version: bigint({ mode: 'bigint' }).notNull(),
  krl: bytea().notNull(),
  generated_at: timestamp({ withTimezone: true }).notNull(),
})

/** A command-line sign-in waiting for the person to approve it in the browser. */
export const cliLogins = pgTable(
  'cli_logins',
  {
    id: id(),
    device_code_hash: text().notNull().unique(),
    /** Shown on both screens so the person can compare them. */
    user_code: text().notNull(),
    /** base64url SHA-256 of the code verifier the CLI keeps. */
    code_challenge: text().notNull(),
    machine_hostname: text().notNull(),
    machine_os: text().notNull(),
    status: cliLoginStatus().notNull().default('pending'),
    user_id: uuid().references(() => users.id, { onDelete: 'cascade' }),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    last_poll_at: timestamp({ withTimezone: true }),
    /** The token was handed out; it is never given twice. */
    consumed_at: timestamp({ withTimezone: true }),
    ip: text(),
    created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('cli_logins_expires_idx').on(t.expires_at)],
)

/** A signed-in command-line client. Acts as the person, with a short life. Only a hash of the token is stored. */
export const cliSessions = pgTable(
  'cli_sessions',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    token_hash: text().notNull().unique(),
    machine_hostname: text().notNull(),
    machine_os: text().notNull(),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    last_used_at: timestamp({ withTimezone: true }),
    revoked_at: timestamp({ withTimezone: true }),
    created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('cli_sessions_user_idx').on(t.user_id), index('cli_sessions_expires_idx').on(t.expires_at)],
)

/**
 * Security keys (YubiKeys) a person registered for SSH, approved in the browser. Host groups
 * that require a security key only sign these. A fingerprint is registered once: a revoked key
 * stays here, so it cannot be registered again.
 */
export const sshSecurityKeys = pgTable(
  'ssh_security_keys',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text().notNull(),
    /** The public key as `<type> <base64>`. */
    public_key: text().notNull(),
    fingerprint: text().notNull(),
    /** The FIDO application the key was made for, e.g. `ssh:certifly`. */
    application: text().notNull(),
    /** Authenticator model from the attestation, lowercase hex; null without one. */
    aaguid: text(),
    /** Subject of the attestation certificate, for the audit trail. */
    attestation_subject: text(),
    /** The attestation chained to a Yubico root, for the challenge certifly gave out. */
    attested: boolean().notNull().default(false),
    /** Host name of the machine whose CLI registered it. */
    machine: text(),
    last_used_at: timestamp({ withTimezone: true }),
    revoked_at: timestamp({ withTimezone: true }),
    revoked_by_user_id: uuid().references(() => users.id, { onDelete: 'set null' }),
    ...timestamps,
  },
  (t) => [uniqueIndex('ssh_security_keys_fingerprint_idx').on(t.fingerprint), index('ssh_security_keys_user_idx').on(t.user_id, t.created_at)],
)

/**
 * Registering a security key: the CLI gets a challenge, makes the key with it and uploads the
 * public key and attestation; the person then approves it in the browser.
 */
export const sshSecurityKeyEnrollments = pgTable(
  'ssh_security_key_enrollments',
  {
    id: id(),
    user_id: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** The CLI session that started it; only that session may upload and poll. */
    cli_session_id: uuid()
      .notNull()
      .references(() => cliSessions.id, { onDelete: 'cascade' }),
    /** 32 random bytes the CLI hands to `ssh-keygen -O challenge=`. Single use. */
    challenge: bytea().notNull(),
    /** Shown in the terminal and on the approval page so the person can compare them. */
    user_code: text().notNull(),
    machine_hostname: text().notNull(),
    machine_os: text().notNull(),
    status: cliLoginStatus().notNull().default('pending'),
    /** The uploaded key, until it is approved. */
    name: text(),
    public_key: text(),
    fingerprint: text(),
    application: text(),
    aaguid: text(),
    attestation_subject: text(),
    attested: boolean().notNull().default(false),
    submitted_at: timestamp({ withTimezone: true }),
    ssh_security_key_id: uuid().references(() => sshSecurityKeys.id, { onDelete: 'set null' }),
    expires_at: timestamp({ withTimezone: true }).notNull(),
    created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('ssh_security_key_enrollments_user_idx').on(t.user_id), index('ssh_security_key_enrollments_expires_idx').on(t.expires_at)],
)
