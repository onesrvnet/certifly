import { type Executor, schema, type Transaction } from '@certifly/db'
import { buildSshCertificate, formatAuthorizedKey, generateSshSerial, parseAuthorizedKey, PkiError, type SshPublicKey } from '@certifly/pki'
import { and, count, desc, eq, gt, ilike, inArray, isNotNull, isNull, lte, ne, or, sql } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { type CursorInput, keyset, paged } from './cursor'
import { AuthorizationError, ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshCertificatePolicy } from './policies'
import { checkRevocationReason, LEAF_REVOCATION_REASONS, type LeafRevocationReason } from './revocation'
import { loadSshCaKey, sshCaSigner, type SshCaRow } from './ssh-cas'
import { resolveSshAccess } from './ssh-access'
import { rebuildSshKrl } from './ssh-krl'

export type SshCertificateRow = typeof schema.sshCertificates.$inferSelect
type HostGroupRow = typeof schema.sshHostGroups.$inferSelect
type SecurityKeyRow = typeof schema.sshSecurityKeys.$inferSelect

/** The start of validity is this far in the past, so small clock differences do not matter. */
export const BACKDATE_MS = 2 * 60 * 1000
export const MIN_RSA_BITS = 2048

export const SSH_CERTIFICATE_REVOCATION_REASONS = LEAF_REVOCATION_REASONS
const subjectOf = (id: string) => ({ type: 'ssh_certificate', id })

/** Parse a user- or host-supplied public key line; any refusal is `ssh_key_type`. */
export async function parseSubmittedKey(line: string, options: { allowSk?: boolean } = {}): Promise<SshPublicKey> {
  try {
    const key = await parseAuthorizedKey(String(line ?? ''), { min_rsa_bits: MIN_RSA_BITS })
    if (key.sk && !options.allowSk) throw new PkiError('invalid_ssh_key', 'Security keys cannot be host keys')
    return key
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, 'ssh_key_type')
    throw error
  }
}

/** A key as stored and compared: `<type> <base64>` without its comment. */
export const plainKeyLine = (key: SshPublicKey) => formatAuthorizedKey(key, '')

interface IssueParams {
  ca: SshCaRow
  kind: 'user' | 'host'
  public_key: SshPublicKey
  principals: string[]
  key_id: (certificate_id: string) => string
  /** Lifetime from now. */
  ttl_seconds: number
  extensions?: readonly string[]
  force_command?: string | null
  source_address?: readonly string[]
  host_group_id: string | null
  user_id?: string | null
  requested_by_user_id?: string | null
  machine?: string | null
  host_id?: string | null
  attested?: boolean
}

/** Sign a certificate with the CA's key and store it, inside the caller's transaction. */
export async function issueSshCertificate(ctx: Context, tx: Transaction, p: IssueParams): Promise<SshCertificateRow> {
  const key = await loadSshCaKey(tx, p.ca.id)
  const signer = sshCaSigner(ctx, key)
  const ca_key = await parseAuthorizedKey(p.ca.public_key)
  const now = Date.now()
  const id = crypto.randomUUID()
  for (let attempt = 0; ; attempt++) {
    const serial = generateSshSerial()
    const cert = await buildSshCertificate({
      type: p.kind,
      public_key: p.public_key,
      ca_key,
      signer,
      serial,
      key_id: p.key_id(id),
      principals: p.principals,
      valid_after: new Date(now - BACKDATE_MS),
      valid_before: new Date(now + p.ttl_seconds * 1000),
      force_command: p.force_command,
      source_address: p.source_address,
      extensions: p.extensions,
    })
    try {
      // A savepoint, so a serial clash (one in 2^63) does not abort the caller's transaction.
      const [row] = await tx.transaction((sp) =>
        sp
          .insert(schema.sshCertificates)
          .values({
            id,
            ssh_ca_id: p.ca.id,
            kind: p.kind,
            serial,
            key_id: cert.key_id,
            principals: cert.principals,
            public_key: plainKeyLine(p.public_key),
            fingerprint: p.public_key.fingerprint,
            certificate: cert.line,
            valid_after: cert.valid_after,
            valid_before: cert.valid_before,
            host_group_id: p.host_group_id,
            user_id: p.user_id ?? null,
            requested_by_user_id: p.requested_by_user_id ?? null,
            machine: p.machine ?? null,
            host_id: p.host_id ?? null,
            attested: p.attested ?? false,
          })
          .returning(),
      )
      return row!
    } catch (error) {
      if (attempt < 3 && isUniqueViolation(error, 'ssh_certificates_serial_idx')) continue
      throw error
    }
  }
}

// ---------------------------------------------------------------------------------------------
// User certificates

export interface SignUserCertificateInput {
  host_group_id: string
  public_key: string
  ttl_seconds?: number
  for_user_id?: string
}

/**
 * Check the host group's key policy. Where a security key is required, it must be one the person
 * registered and approved (`ssh_key_not_registered` otherwise); `sk_attested` also needs it to
 * have been registered with a genuine Yubico attestation. A revoked security key is never signed,
 * whatever the policy. Returns the person's registered key when the submitted key is one.
 */
async function checkKeyPolicy(db: Executor, group: HostGroupRow, user_id: string, key: SshPublicKey): Promise<SecurityKeyRow | null> {
  const k = schema.sshSecurityKeys
  const [registered] = key.sk ? await db.select().from(k).where(eq(k.fingerprint, key.fingerprint)) : []
  if (registered?.revoked_at) throw new ValidationError('This security key was revoked', 'ssh_key_revoked')
  const own = registered && registered.user_id === user_id ? registered : null
  if (group.key_policy === 'any') return own
  if (!key.sk) throw new ValidationError('This host group needs a security key (ed25519-sk or ecdsa-sk)', 'ssh_key_policy')
  if (!own) throw new AuthorizationError('This security key is not registered. Register it with the certifly CLI first.', 'ssh_key_not_registered')
  if (group.key_policy === 'sk_attested' && !own.attested) throw new ValidationError('This host group needs a YubiKey registered with a genuine Yubico attestation', 'ssh_key_policy')
  return own
}

/**
 * Sign a person's public key for one host group. The key must satisfy the group's key policy,
 * the person needs at least one login in the group (through their groups), and the lifetime
 * may not exceed the group's maximum. Operators and admins may sign for someone else
 * (`for_user_id`); that person's own access rules and registered security keys apply.
 */
export async function signUserCertificate(ctx: Context, actor: Actor, input: SignUserCertificateInput) {
  const target_id = input.for_user_id ?? actor.id
  const for_others = target_id !== actor.id
  if (for_others) {
    authorize(sshCertificatePolicy, actor, 'sign_for_others', undefined)
    assertStepUp(actor)
  }

  const [user] = await ctx.db.select().from(schema.users).where(and(eq(schema.users.id, target_id), isNull(schema.users.deleted_at)))
  if (!user) throw new NotFoundError('User not found')
  const public_key = await parseSubmittedKey(input.public_key, { allowSk: true })

  const { access } = await resolveSshAccess(ctx.db, user)
  const entry = access.find((a) => a.host_group.id === input.host_group_id)
  if (!entry) throw new AuthorizationError('You have no access to this host group', 'ssh_no_access')
  const group = entry.host_group

  const ttl = input.ttl_seconds ?? group.user_ttl_default_seconds
  if (!Number.isInteger(ttl) || ttl < 60) throw new ValidationError('ttl_seconds must be a whole number of at least 60', 'invalid_ttl')
  if (ttl > group.user_ttl_max_seconds) throw new ValidationError(`The longest lifetime in this host group is ${group.user_ttl_max_seconds} seconds`, 'ttl_too_long', { max_ttl_seconds: group.user_ttl_max_seconds })
  const security_key = await checkKeyPolicy(ctx.db, group, user.id, public_key)
  const attested = security_key?.attested ?? false
  // A CLI renewing for its own person replaces its earlier certificate; other machines keep theirs.
  let machine: string | null = null
  if (actor.cli_session_id && !for_others) {
    const [session] = await ctx.db.select({ machine: schema.cliSessions.machine_hostname }).from(schema.cliSessions).where(eq(schema.cliSessions.id, actor.cli_session_id))
    machine = session?.machine ?? null
  }

  return withTransaction(ctx, async (tx) => {
    const row = await issueSshCertificate(ctx, tx, {
      ca: entry.ca,
      kind: 'user',
      public_key,
      principals: entry.principals,
      key_id: (id) => `certifly:${user.email}:${group.slug}:${id}`,
      ttl_seconds: ttl,
      extensions: group.user_extensions,
      force_command: group.force_command,
      source_address: group.source_address,
      host_group_id: group.id,
      user_id: user.id,
      requested_by_user_id: for_others ? actor.id : null,
      machine,
      attested,
    })
    if (security_key) await tx.update(schema.sshSecurityKeys).set({ last_used_at: new Date() }).where(eq(schema.sshSecurityKeys.id, security_key.id))
    if (machine) {
      const c = schema.sshCertificates
      const older = await tx
        .select({ id: c.id })
        .from(c)
        .where(and(eq(c.kind, 'user'), eq(c.user_id, user.id), eq(c.host_group_id, group.id), eq(c.machine, machine), isNull(c.revoked_at), gt(c.valid_before, new Date()), ne(c.id, row.id)))
      if (older.length) await revokeSshCertificatesIn(ctx, tx, actor, older.map((r) => r.id), 'superseded')
    }
    await recordEvent(
      ctx,
      eventFor(actor, 'ssh_certificates.issue', subjectOf(row.id), {
        kind: 'user',
        host_group_id: group.id,
        user_id: user.id,
        serial: row.serial.toString(),
        principals: row.principals,
        fingerprint: row.fingerprint,
        valid_before: row.valid_before.toISOString(),
        attested,
      }),
      tx,
    )
    return row
  })
}

// ---------------------------------------------------------------------------------------------
// Listing and revoking

export interface ListSshCertificatesInput extends CursorInput {
  kind?: 'user' | 'host'
  user_id?: string
  host_id?: string
  host_group_id?: string
  ssh_ca_id?: string
  status?: 'active' | 'revoked' | 'expired'
  /** Matches the key ID and the principals, ignoring case. */
  query?: string
}

export type SshCertificateListRow = SshCertificateRow & {
  user: { id: string; name: string; email: string } | null
  host: { id: string; name: string } | null
  host_group: { id: string; slug: string; name: string } | null
}

/**
 * Certificates, newest first. Operators and admins see every certificate; everyone else sees
 * only their own user certificates.
 */
export async function listSshCertificates(ctx: Context, actor: Actor, input: ListSshCertificatesInput) {
  authorize(sshCertificatePolicy, actor, 'read', undefined)
  const c = schema.sshCertificates
  const operator = sshCertificatePolicy.can(actor, 'read', { kind: 'host', user_id: null })
  const now = new Date()
  const page = keyset(
    [
      { expr: c.created_at, type: 'timestamptz', direction: 'desc' },
      { expr: c.id, type: 'uuid', direction: 'desc' },
    ],
    input,
  )
  const search = input.query?.trim()
  const pattern = search ? `%${search.replace(/[\\%_]/g, '\\$&')}%` : null
  // What every count shares with the list: who may see it and the filters other than kind and status.
  const scope = and(
    operator ? undefined : and(eq(c.kind, 'user'), eq(c.user_id, actor.id)),
    input.user_id ? eq(c.user_id, input.user_id) : undefined,
    input.host_id ? eq(c.host_id, input.host_id) : undefined,
    input.host_group_id ? eq(c.host_group_id, input.host_group_id) : undefined,
    input.ssh_ca_id ? eq(c.ssh_ca_id, input.ssh_ca_id) : undefined,
    pattern ? or(ilike(c.key_id, pattern), sql`array_to_string(${c.principals}, ' ') ilike ${pattern}`) : undefined,
  )
  const [rows, [totals]] = await Promise.all([
    ctx.db
      .select({
        cursor_keys: page.keys,
        cert: c,
        user: { id: schema.users.id, name: schema.users.name, email: schema.users.email },
        host: { id: schema.sshHosts.id, name: schema.sshHosts.name },
        host_group: { id: schema.sshHostGroups.id, slug: schema.sshHostGroups.slug, name: schema.sshHostGroups.name },
      })
      .from(c)
      .leftJoin(schema.users, eq(schema.users.id, c.user_id))
      .leftJoin(schema.sshHosts, eq(schema.sshHosts.id, c.host_id))
      .leftJoin(schema.sshHostGroups, eq(schema.sshHostGroups.id, c.host_group_id))
      .where(
        and(
          scope,
          input.kind ? eq(c.kind, input.kind) : undefined,
          input.status === 'revoked' ? isNotNull(c.revoked_at) : undefined,
          input.status === 'active' ? and(isNull(c.revoked_at), gt(c.valid_before, now)) : undefined,
          input.status === 'expired' ? and(isNull(c.revoked_at), lte(c.valid_before, now)) : undefined,
          page.where,
        ),
      )
      .orderBy(...page.orderBy)
      .limit(page.limit),
    ctx.db
      .select({
        all: count(),
        user: sql<number>`count(*) filter (where ${c.kind} = 'user')`.mapWith(Number),
        host: sql<number>`count(*) filter (where ${c.kind} = 'host')`.mapWith(Number),
        revoked: sql<number>`count(*) filter (where ${c.revoked_at} is not null)`.mapWith(Number),
      })
      .from(c)
      .where(scope),
  ])
  const result = paged(rows, input.limit)
  return {
    rows: result.rows.map((r): SshCertificateListRow => ({ ...r.cert, user: r.user?.id ? r.user : null, host: r.host?.id ? r.host : null, host_group: r.host_group?.id ? r.host_group : null })),
    next_cursor: result.next_cursor,
    counts: { all: totals?.all ?? 0, user: totals?.user ?? 0, host: totals?.host ?? 0, revoked: totals?.revoked ?? 0 },
  }
}

async function findReadable(db: Executor, actor: Actor, id: string): Promise<SshCertificateRow> {
  const [row] = await db.select().from(schema.sshCertificates).where(eq(schema.sshCertificates.id, id))
  if (!row || !sshCertificatePolicy.can(actor, 'read', row)) throw new NotFoundError('Certificate not found')
  return row
}

export async function getSshCertificate(ctx: Context, actor: Actor, id: string): Promise<SshCertificateListRow> {
  const row = await findReadable(ctx.db, actor, id)
  const [user] = row.user_id ? await ctx.db.select({ id: schema.users.id, name: schema.users.name, email: schema.users.email }).from(schema.users).where(eq(schema.users.id, row.user_id)) : []
  const [host] = row.host_id ? await ctx.db.select({ id: schema.sshHosts.id, name: schema.sshHosts.name }).from(schema.sshHosts).where(eq(schema.sshHosts.id, row.host_id)) : []
  const [host_group] = row.host_group_id
    ? await ctx.db.select({ id: schema.sshHostGroups.id, slug: schema.sshHostGroups.slug, name: schema.sshHostGroups.name }).from(schema.sshHostGroups).where(eq(schema.sshHostGroups.id, row.host_group_id))
    : []
  return { ...row, user: user ?? null, host: host ?? null, host_group: host_group ?? null }
}

/**
 * Mark certificates revoked and rebuild the revocation list of every CA affected, in the
 * caller's transaction. Already revoked and expired ones are left alone. Returns the ones that changed.
 */
export async function revokeSshCertificatesIn(ctx: Context, tx: Transaction, actor: Parameters<typeof eventFor>[0] | null, ids: readonly string[], reason: LeafRevocationReason, eventName = 'ssh_certificates.revoke'): Promise<SshCertificateRow[]> {
  if (!ids.length) return []
  const c = schema.sshCertificates
  const now = new Date()
  const rows = await tx
    .update(c)
    .set({ revoked_at: now, revocation_reason: reason })
    .where(and(inArray(c.id, [...ids]), isNull(c.revoked_at), gt(c.valid_before, now)))
    .returning()
  for (const ca of new Set(rows.map((r) => r.ssh_ca_id))) await rebuildSshKrl(tx, ca, now)
  for (const row of rows) {
    const data = { kind: row.kind, serial: row.serial.toString(), reason }
    await recordEvent(ctx, actor ? eventFor(actor, eventName, subjectOf(row.id), data) : { actor_type: 'system', name: eventName, subject_type: 'ssh_certificate', subject_id: row.id, data }, tx)
  }
  return rows
}

/**
 * Revoke a certificate: it goes on the CA's revocation list, which is rebuilt in the same
 * transaction, so the next fetch by a host already includes it. People revoke their own user
 * certificates; operators and admins revoke any.
 */
export async function revokeSshCertificate(ctx: Context, actor: Actor, id: string, input: { reason?: string } = {}): Promise<SshCertificateRow> {
  const reason = checkRevocationReason(LEAF_REVOCATION_REASONS, input.reason ?? 'unspecified')
  return withTransaction(ctx, async (tx) => {
    const [row] = await tx.select().from(schema.sshCertificates).where(eq(schema.sshCertificates.id, id)).for('update')
    if (!row || !sshCertificatePolicy.can(actor, 'read', row)) throw new NotFoundError('Certificate not found')
    authorize(sshCertificatePolicy, actor, 'revoke', row)
    if (row.revoked_at) return row
    if (row.valid_before <= new Date()) throw new ConflictError('The certificate has expired; there is nothing left to revoke', 'certificate_not_revocable')
    await revokeSshCertificatesIn(ctx, tx, actor, [id], reason)
    const [updated] = await tx.select().from(schema.sshCertificates).where(eq(schema.sshCertificates.id, id))
    return updated!
  })
}

/** Revoke every valid user certificate of a person, e.g. when they are deactivated. */
export async function revokeUserSshCertificates(ctx: Context, tx: Transaction, actor: Actor, user_id: string): Promise<number> {
  const c = schema.sshCertificates
  const rows = await tx
    .select({ id: c.id })
    .from(c)
    .where(and(eq(c.kind, 'user'), eq(c.user_id, user_id), isNull(c.revoked_at), gt(c.valid_before, new Date())))
  const revoked = await revokeSshCertificatesIn(ctx, tx, actor, rows.map((r) => r.id), 'privilege_withdrawn')
  return revoked.length
}

/** The newest valid host certificate per host, for lists. */
export async function currentHostCertificates(db: Executor, host_ids: readonly string[]) {
  if (!host_ids.length) return new Map<string, SshCertificateRow>()
  const c = schema.sshCertificates
  const rows = await db
    .select()
    .from(c)
    .where(and(eq(c.kind, 'host'), inArray(c.host_id, [...host_ids]), isNull(c.revoked_at), gt(c.valid_before, new Date())))
    .orderBy(desc(c.valid_before))
  const out = new Map<string, SshCertificateRow>()
  for (const row of rows) if (row.host_id && !out.has(row.host_id)) out.set(row.host_id, row)
  return out
}

