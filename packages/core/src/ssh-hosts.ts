import { type Executor, schema, type Transaction } from '@certifly/db'
import { isValidDnsName, parseIp, verifySshsig } from '@certifly/pki'
import { and, asc, eq, gt, ilike, inArray, isNull, ne, or, sql } from 'drizzle-orm'
import { eventFor, type NewEvent, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { randomToken, sha256 } from './crypto'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { AuthenticationError, AuthorizationError, ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshHostPolicy, sshJoinTokenPolicy } from './policies'
import { loadSshCaKey, type SshCaRow } from './ssh-cas'
import { type SshCertificateRow, currentHostCertificates, issueSshCertificate, parseSubmittedKey, plainKeyLine, revokeSshCertificatesIn } from './ssh-certificates'
import { loadSshHostGroup, matchesHostPatterns } from './ssh-host-groups'
import { hasControlCharacters } from './text'

export type SshHostRow = typeof schema.sshHosts.$inferSelect
export type SshJoinTokenRow = typeof schema.sshJoinTokens.$inferSelect

export const JOIN_TOKEN_PREFIX = 'cfj_'
export const JOIN_TOKEN_DEFAULT_TTL_SECONDS = 24 * 3600
export const JOIN_TOKEN_MAX_TTL_SECONDS = 7 * 24 * 3600
export const HOST_CHALLENGE_TTL_MS = 5 * 60 * 1000
export const HOST_SYNC_INTERVAL_SECONDS = 900
/** Namespace of the SSHSIG a host signs over its nonce. */
export const HOST_SIGNATURE_NAMESPACE = 'certifly-host@certifly'
const MAX_HOSTNAMES = 20
const MAX_HOST_KEYS = 10
const MAX_OPEN_CHALLENGES = 10

const hostSubject = (id: string) => ({ type: 'ssh_host', id })

/** An audit event for what a host did with its own key or a join token. */
function hostEvent(host_id: string | null, name: string, subject: { type: string; id: string }, data: Record<string, unknown> = {}, ip: string | null = null): NewEvent {
  return { actor_type: 'ssh_host', actor_id: host_id, name, subject_type: subject.type, subject_id: subject.id, data, ip }
}

// ---------------------------------------------------------------------------------------------
// Input checks

function checkHostnames(list: readonly string[] | undefined, patterns: readonly string[]): string[] {
  const names = [...new Set((list ?? []).map((n) => String(n).trim().toLowerCase()).filter(Boolean))]
  if (!names.length || names.length > MAX_HOSTNAMES) throw new ValidationError(`Give 1 to ${MAX_HOSTNAMES} host names`, 'invalid_hostname')
  for (const name of names) {
    if (!isValidDnsName(name) && parseIp(name) === null) throw new ValidationError(`Not a valid host name: ${name.slice(0, 80)}`, 'invalid_hostname')
    if (!matchesHostPatterns(name, patterns)) throw new ValidationError(`The host name ${name} does not match this host group's patterns`, 'host_name_not_allowed')
  }
  return names
}

async function checkHostKeys(list: readonly string[] | undefined) {
  const keys = []
  const seen = new Set<string>()
  for (const line of list ?? []) {
    const key = await parseSubmittedKey(line)
    if (seen.has(key.fingerprint)) continue
    seen.add(key.fingerprint)
    keys.push(key)
  }
  if (!keys.length || keys.length > MAX_HOST_KEYS) throw new ValidationError(`Give 1 to ${MAX_HOST_KEYS} host keys`, 'invalid_host_keys')
  return keys
}

function checkName(name: string): string {
  const value = String(name ?? '').trim()
  if (!value || value.length > 253) throw new ValidationError('The name must be 1 to 253 characters')
  if (hasControlCharacters(value)) throw new ValidationError('The name may not contain line breaks or control characters')
  return value
}

/**
 * A host certificate for a name another host holds would let one host impersonate the other,
 * so no two hosts share a host name, whatever their host groups or CAs. The lock serialises
 * the check with the insert or update that follows; it is released when the transaction ends.
 */
async function assertHostnamesFree(tx: Transaction, hostnames: string[], except: string | null) {
  await tx.execute(sql`select pg_advisory_xact_lock(hashtext('certifly.ssh_hosts.hostnames'))`)
  const h = schema.sshHosts
  const list = sql`array[${sql.join(hostnames.map((n) => sql`${n}`), sql`, `)}]::text[]`
  const [other] = await tx
    .select({ hostnames: h.hostnames })
    .from(h)
    .where(and(sql`${h.hostnames} && ${list}`, except ? ne(h.id, except) : undefined))
    .limit(1)
  if (!other) return
  const taken = hostnames.find((n) => other.hostnames.includes(n)) ?? hostnames[0]!
  throw new ConflictError(`Another host already uses the name ${taken}`, 'hostname_taken')
}

function nameTaken(error: unknown): never {
  if (isUniqueViolation(error, 'ssh_hosts_name_lower_idx')) throw new ConflictError('Another host already has this name', 'host_name_taken')
  throw error
}

// ---------------------------------------------------------------------------------------------
// Host certificates and what a host receives

export interface HostSync {
  host: { id: string; name: string; host_group: { id: string; slug: string; name: string } }
  certificates: string[]
  ca_public_key: string
  krl_url: string
  principals: { fixed: Record<string, string[]>; own_username: boolean }
  sync_interval_seconds: number
}

async function hostPrincipals(db: Executor, host_group_id: string, slug: string) {
  const rules = await db.select({ logins: schema.sshAccessRules.logins, own_username: schema.sshAccessRules.own_username }).from(schema.sshAccessRules).where(eq(schema.sshAccessRules.host_group_id, host_group_id))
  const fixed: Record<string, string[]> = {}
  for (const login of new Set(rules.flatMap((r) => r.logins))) fixed[login] = [`${slug}:${login}`]
  return { fixed, own_username: rules.some((r) => r.own_username) }
}

/**
 * Make sure the host has a valid certificate for every registered key, issuing new ones where
 * none is left or less than a third of the lifetime remains. Returns the current certificates.
 */
async function ensureHostCertificates(ctx: Context, tx: Transaction, host: SshHostRow, group: typeof schema.sshHostGroups.$inferSelect, ca: SshCaRow): Promise<SshCertificateRow[]> {
  if (!host.hostnames.every((n) => matchesHostPatterns(n, group.host_patterns))) {
    throw new ValidationError("The host's names no longer match its host group's patterns", 'host_name_not_allowed')
  }
  const c = schema.sshCertificates
  const now = Date.now()
  const existing = await tx
    .select()
    .from(c)
    .where(and(eq(c.kind, 'host'), eq(c.host_id, host.id), isNull(c.revoked_at), gt(c.valid_before, new Date(now))))
  const out: SshCertificateRow[] = []
  for (const line of host.public_keys) {
    const key = await parseSubmittedKey(line)
    const current = existing
      .filter((cert) => cert.fingerprint === key.fingerprint && cert.ssh_ca_id === ca.id && cert.principals.join(',') === host.hostnames.join(','))
      .sort((a, b) => b.valid_before.getTime() - a.valid_before.getTime())[0]
    const renew = !current || current.valid_before.getTime() - now < (current.valid_before.getTime() - current.valid_after.getTime()) / 3
    if (!renew) {
      out.push(current!)
      continue
    }
    const row = await issueSshCertificate(ctx, tx, {
      ca,
      kind: 'host',
      public_key: key,
      principals: host.hostnames,
      key_id: (id) => `certifly:host:${host.hostnames[0]}:${id}`,
      ttl_seconds: group.host_ttl_seconds,
      host_group_id: group.id,
      host_id: host.id,
    })
    await recordEvent(ctx, hostEvent(host.id, 'ssh_certificates.issue', { type: 'ssh_certificate', id: row.id }, { kind: 'host', host_id: host.id, serial: row.serial.toString(), principals: row.principals, valid_before: row.valid_before.toISOString() }), tx)
    out.push(row)
  }
  return out
}

async function buildHostSync(ctx: Context, tx: Transaction, host: SshHostRow): Promise<HostSync> {
  const group = await loadSshHostGroup(tx, host.host_group_id)
  const [ca] = await tx.select().from(schema.sshCas).where(eq(schema.sshCas.id, group.ssh_ca_id))
  if (!ca) throw new NotFoundError('SSH certificate authority not found')
  await loadSshCaKey(tx, ca.id)
  const certificates = await ensureHostCertificates(ctx, tx, host, group, ca)
  return {
    host: { id: host.id, name: host.name, host_group: { id: group.id, slug: group.slug, name: group.name } },
    certificates: certificates.map((cert) => cert.certificate),
    ca_public_key: ca.public_key,
    krl_url: `${ctx.pki_base_url}/api/pki/ssh/${ca.slug}.krl`,
    principals: await hostPrincipals(tx, group.id, group.slug),
    sync_interval_seconds: HOST_SYNC_INTERVAL_SECONDS,
  }
}

/** Revoke every valid certificate of a host, e.g. when its names, keys or group change or it is deleted. */
async function revokeHostCertificates(ctx: Context, tx: Transaction, actor: Actor, host_id: string, reason: 'superseded' | 'cessation_of_operation') {
  const c = schema.sshCertificates
  const rows = await tx.select({ id: c.id }).from(c).where(and(eq(c.kind, 'host'), eq(c.host_id, host_id), isNull(c.revoked_at), gt(c.valid_before, new Date())))
  return revokeSshCertificatesIn(ctx, tx, actor, rows.map((r) => r.id), reason)
}

// ---------------------------------------------------------------------------------------------
// Join tokens

export interface CreateJoinTokenInput {
  host_group_id: string
  label?: string
  ttl_seconds?: number
}

/** A new single-use token for enrolling a host into a host group. Returned once; only its hash is kept. */
export async function createJoinToken(ctx: Context, actor: Actor, input: CreateJoinTokenInput): Promise<{ row: SshJoinTokenRow; token: string }> {
  authorize(sshJoinTokenPolicy, actor, 'create', undefined)
  assertStepUp(actor)
  const ttl = input.ttl_seconds ?? JOIN_TOKEN_DEFAULT_TTL_SECONDS
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > JOIN_TOKEN_MAX_TTL_SECONDS) throw new ValidationError(`ttl_seconds must be from 60 to ${JOIN_TOKEN_MAX_TTL_SECONDS}`, 'invalid_ttl')
  const label = String(input.label ?? '').trim().slice(0, 100)
  const token = `${JOIN_TOKEN_PREFIX}${randomToken(30)}`
  return withTransaction(ctx, async (tx) => {
    await loadSshHostGroup(tx, input.host_group_id)
    const [row] = await tx
      .insert(schema.sshJoinTokens)
      .values({ host_group_id: input.host_group_id, label, token_hash: sha256(token), last4: token.slice(-4), expires_at: new Date(Date.now() + ttl * 1000), created_by_user_id: actor.id })
      .returning()
    await recordEvent(ctx, eventFor(actor, 'ssh_join_tokens.create', { type: 'ssh_join_token', id: row!.id }, { host_group_id: input.host_group_id, label, expires_at: row!.expires_at.toISOString() }), tx)
    return { row: row!, token }
  })
}

export type SshJoinTokenListRow = SshJoinTokenRow & { host_group: { id: string; slug: string; name: string }; host: { id: string; name: string } | null; created_by: { id: string; name: string } | null }

export async function listJoinTokens(ctx: Context, actor: Actor, input: CursorInput & { host_group_id?: string; status?: 'open' | 'used' | 'expired' }) {
  authorize(sshJoinTokenPolicy, actor, 'read', undefined)
  const t = schema.sshJoinTokens
  const now = new Date()
  const page = keyset(
    [
      { expr: t.created_at, type: 'timestamptz', direction: 'desc' },
      { expr: t.id, type: 'uuid', direction: 'desc' },
    ],
    input,
  )
  const rows = await ctx.db
    .select({
      cursor_keys: page.keys,
      token: t,
      host_group: { id: schema.sshHostGroups.id, slug: schema.sshHostGroups.slug, name: schema.sshHostGroups.name },
      host: { id: schema.sshHosts.id, name: schema.sshHosts.name },
      created_by: { id: schema.users.id, name: schema.users.name },
    })
    .from(t)
    .innerJoin(schema.sshHostGroups, eq(schema.sshHostGroups.id, t.host_group_id))
    .leftJoin(schema.sshHosts, eq(schema.sshHosts.id, t.host_id))
    .leftJoin(schema.users, eq(schema.users.id, t.created_by_user_id))
    .where(
      and(
        input.host_group_id ? eq(t.host_group_id, input.host_group_id) : undefined,
        input.status === 'used' ? sql`${t.used_at} is not null` : undefined,
        input.status === 'open' ? and(isNull(t.used_at), gt(t.expires_at, now)) : undefined,
        input.status === 'expired' ? and(isNull(t.used_at), sql`${t.expires_at} <= ${now.toISOString()}::timestamptz`) : undefined,
        page.where,
      ),
    )
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return { rows: result.rows.map((r): SshJoinTokenListRow => ({ ...r.token, host_group: r.host_group, host: r.host?.id ? r.host : null, created_by: r.created_by?.id ? r.created_by : null })), next_cursor: result.next_cursor }
}

export async function deleteJoinToken(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(sshJoinTokenPolicy, actor, 'delete', undefined)
  await withTransaction(ctx, async (tx) => {
    const [row] = await tx.delete(schema.sshJoinTokens).where(eq(schema.sshJoinTokens.id, id)).returning()
    if (!row) throw new NotFoundError('Join token not found')
    await recordEvent(ctx, eventFor(actor, 'ssh_join_tokens.delete', { type: 'ssh_join_token', id }, { host_group_id: row.host_group_id, used: row.used_at !== null }), tx)
  })
}

// ---------------------------------------------------------------------------------------------
// Enrolling and syncing hosts (no sign-in: join token or host key)

/**
 * A host enrols with a join token: the token is spent, the host is registered with its names
 * and keys, and it receives a host certificate for each key. The names must match the host
 * group's patterns.
 */
export async function joinSshHost(ctx: Context, input: { token: string; hostnames: string[]; public_keys: string[]; ip?: string | null }): Promise<HostSync> {
  const invalid = () => new AuthenticationError('The join token is not valid', 'invalid_token')
  const token = String(input.token ?? '')
  if (!token.startsWith(JOIN_TOKEN_PREFIX)) throw invalid()
  const keys = await checkHostKeys(input.public_keys)
  try {
    return await withTransaction(ctx, async (tx) => {
      const [row] = await tx.select().from(schema.sshJoinTokens).where(eq(schema.sshJoinTokens.token_hash, sha256(token))).for('update')
      if (!row || row.used_at || row.expires_at <= new Date()) throw invalid()
      const group = await loadSshHostGroup(tx, row.host_group_id)
      const hostnames = checkHostnames(input.hostnames, group.host_patterns)
      await assertHostnamesFree(tx, hostnames, null)
      const [host] = await tx
        .insert(schema.sshHosts)
        .values({ name: hostnames[0]!, host_group_id: group.id, hostnames, public_keys: keys.map(plainKeyLine), last_seen_at: new Date(), created_by_user_id: row.created_by_user_id })
        .returning()
      await tx.update(schema.sshJoinTokens).set({ used_at: new Date(), host_id: host!.id }).where(eq(schema.sshJoinTokens.id, row.id))
      await recordEvent(ctx, hostEvent(host!.id, 'ssh_hosts.join', hostSubject(host!.id), { host_group_id: group.id, join_token_id: row.id, hostnames }, input.ip ?? null), tx)
      return buildHostSync(ctx, tx, host!)
    })
  } catch (error) {
    return nameTaken(error)
  }
}

/** A single-use nonce the host signs with one of its registered keys. */
export async function createHostChallenge(ctx: Context, input: { host_id: string }) {
  const nonce = randomToken(32)
  const expires_at = new Date(Date.now() + HOST_CHALLENGE_TTL_MS)
  await withTransaction(ctx, async (tx) => {
    const [host] = await tx.select({ id: schema.sshHosts.id }).from(schema.sshHosts).where(eq(schema.sshHosts.id, input.host_id))
    if (!host) throw new NotFoundError('Host not found')
    // Anyone may ask for a challenge, so keep the table from filling up: drop what has run out
    // and cap what is open.
    const h = schema.sshHostChallenges
    await tx.delete(h).where(and(eq(h.host_id, host.id), sql`${h.expires_at} <= now()`))
    // At the cap the oldest open challenge makes room. Refusing instead would let anyone who
    // knows the host id keep it from syncing; an evicted host simply retries at its next sync.
    const open = await tx.select({ id: h.id }).from(h).where(and(eq(h.host_id, host.id), isNull(h.used_at))).orderBy(asc(h.created_at)).for('update')
    const evict = open.slice(0, Math.max(0, open.length - MAX_OPEN_CHALLENGES + 1)).map((c) => c.id)
    if (evict.length) await tx.delete(h).where(inArray(h.id, evict))
    await tx.insert(h).values({ host_id: host.id, nonce_hash: sha256(nonce), expires_at })
  })
  return { nonce, expires_at }
}

export interface SyncHostInput {
  host_id: string
  nonce: string
  /** Armored SSHSIG over the nonce text (UTF-8, no newline), namespace `certifly-host@certifly`. */
  signature: string
  public_keys: string[]
  ip?: string | null
}

/**
 * The host proves itself with a signature over a fresh nonce made by one of its registered
 * keys, then gets its certificates renewed where less than a third of their lifetime is left.
 * A changed key list (host key rotation) is accepted only because the signature came from a key
 * that was registered before; certificates of keys that left the list are revoked.
 */
export async function syncSshHost(ctx: Context, input: SyncHostInput): Promise<HostSync> {
  const refused = () => new AuthorizationError('The host could not be verified', 'host_not_verified')
  const nonce = String(input.nonce ?? '')
  const keys = await checkHostKeys(input.public_keys)
  // Spend the nonce first and outside the transaction below, so a failed attempt cannot give
  // it back: whatever happens next, it cannot be used a second time.
  const h = schema.sshHostChallenges
  const [challenge] = await ctx.db
    .update(h)
    .set({ used_at: new Date() })
    .where(and(eq(h.nonce_hash, sha256(nonce)), eq(h.host_id, input.host_id), isNull(h.used_at), gt(h.expires_at, new Date())))
    .returning()
  if (!challenge) throw refused()
  return withTransaction(ctx, async (tx) => {
    const [host] = await tx.select().from(schema.sshHosts).where(eq(schema.sshHosts.id, input.host_id)).for('update')
    if (!host) throw refused()
    let signer
    try {
      signer = (await verifySshsig(String(input.signature ?? ''), new TextEncoder().encode(nonce), HOST_SIGNATURE_NAMESPACE)).public_key
    } catch {
      throw refused()
    }
    if (!host.public_keys.includes(plainKeyLine(signer))) throw refused()

    const next = keys.map(plainKeyLine)
    const changed = next.length !== host.public_keys.length || next.some((k) => !host.public_keys.includes(k))
    let current = host
    if (changed) {
      const gone = host.public_keys.filter((k) => !next.includes(k))
      const [updated] = await tx.update(schema.sshHosts).set({ public_keys: next, last_seen_at: new Date() }).where(eq(schema.sshHosts.id, host.id)).returning()
      current = updated!
      if (gone.length) {
        const c = schema.sshCertificates
        const old = await tx.select({ id: c.id }).from(c).where(and(eq(c.kind, 'host'), eq(c.host_id, host.id), isNull(c.revoked_at), inArray(c.public_key, gone)))
        await revokeSshCertificatesIn(ctx, tx, null, old.map((r) => r.id), 'superseded')
      }
      await recordEvent(ctx, hostEvent(host.id, 'ssh_hosts.rotate_keys', hostSubject(host.id), { keys: next.length, removed: gone.length }, input.ip ?? null), tx)
    } else {
      await tx.update(schema.sshHosts).set({ last_seen_at: new Date() }).where(eq(schema.sshHosts.id, host.id))
    }
    return buildHostSync(ctx, tx, current)
  })
}

// ---------------------------------------------------------------------------------------------
// The registry (operators and admins)

export interface SshHostInput {
  name?: string
  host_group_id?: string
  hostnames?: string[]
  public_keys?: string[]
}

/** Add a host by hand. Its certificates are issued when it first syncs. */
export async function createSshHost(ctx: Context, actor: Actor, input: Required<Pick<SshHostInput, 'host_group_id' | 'hostnames' | 'public_keys'>> & { name?: string }): Promise<SshHostRow> {
  authorize(sshHostPolicy, actor, 'manage', undefined)
  try {
    return await withTransaction(ctx, async (tx) => {
      const group = await loadSshHostGroup(tx, input.host_group_id)
      const hostnames = checkHostnames(input.hostnames, group.host_patterns)
      const keys = await checkHostKeys(input.public_keys)
      await assertHostnamesFree(tx, hostnames, null)
      const name = input.name !== undefined ? checkName(input.name) : hostnames[0]!
      const [row] = await tx
        .insert(schema.sshHosts)
        .values({ name, host_group_id: group.id, hostnames, public_keys: keys.map(plainKeyLine), created_by_user_id: actor.id })
        .returning()
      await recordEvent(ctx, eventFor(actor, 'ssh_hosts.create', hostSubject(row!.id), { host_group_id: group.id, hostnames }), tx)
      return row!
    })
  } catch (error) {
    return nameTaken(error)
  }
}

/**
 * Change a host. Changing its names, keys or host group revokes its valid certificates (they
 * no longer describe it); new ones are issued when it next syncs.
 */
export async function updateSshHost(ctx: Context, actor: Actor, id: string, input: SshHostInput): Promise<SshHostRow> {
  authorize(sshHostPolicy, actor, 'manage', undefined)
  try {
    return await withTransaction(ctx, async (tx) => {
      const [current] = await tx.select().from(schema.sshHosts).where(eq(schema.sshHosts.id, id)).for('update')
      if (!current) throw new NotFoundError('Host not found')
      const group = await loadSshHostGroup(tx, input.host_group_id ?? current.host_group_id)
      const set: Partial<typeof schema.sshHosts.$inferInsert> = {}
      let identityChanged = false
      if (input.name !== undefined) set.name = checkName(input.name)
      if (input.host_group_id !== undefined && input.host_group_id !== current.host_group_id) {
        set.host_group_id = group.id
        identityChanged = true
      }
      if (input.hostnames !== undefined || set.host_group_id) {
        const hostnames = checkHostnames(input.hostnames ?? current.hostnames, group.host_patterns)
        if (hostnames.join(',') !== current.hostnames.join(',')) {
          await assertHostnamesFree(tx, hostnames, current.id)
          identityChanged = true
        }
        set.hostnames = hostnames
      }
      if (input.public_keys !== undefined) {
        const next = (await checkHostKeys(input.public_keys)).map(plainKeyLine)
        if (next.length !== current.public_keys.length || next.some((k) => !current.public_keys.includes(k))) identityChanged = true
        set.public_keys = next
      }
      if (!Object.keys(set).length) return current
      const [row] = await tx.update(schema.sshHosts).set(set).where(eq(schema.sshHosts.id, id)).returning()
      const revoked = identityChanged ? await revokeHostCertificates(ctx, tx, actor, id, 'superseded') : []
      await recordEvent(ctx, eventFor(actor, 'ssh_hosts.update', hostSubject(id), { fields: Object.keys(set), certificates_revoked: revoked.length }), tx)
      return row!
    })
  } catch (error) {
    return nameTaken(error)
  }
}

/** Remove a host and revoke its valid certificates. */
export async function deleteSshHost(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(sshHostPolicy, actor, 'manage', undefined)
  await withTransaction(ctx, async (tx) => {
    const [host] = await tx.select().from(schema.sshHosts).where(eq(schema.sshHosts.id, id)).for('update')
    if (!host) throw new NotFoundError('Host not found')
    const revoked = await revokeHostCertificates(ctx, tx, actor, id, 'cessation_of_operation')
    await tx.delete(schema.sshHosts).where(eq(schema.sshHosts.id, id))
    await recordEvent(ctx, eventFor(actor, 'ssh_hosts.delete', hostSubject(id), { name: host.name, certificates_revoked: revoked.length }), tx)
  })
}

export type SshHostListRow = SshHostRow & { host_group: { id: string; slug: string; name: string }; certificate: SshCertificateRow | null }

async function withCertificates(db: Executor, rows: { host: SshHostRow; host_group: { id: string; slug: string; name: string } }[]): Promise<SshHostListRow[]> {
  const certs = await currentHostCertificates(db, rows.map((r) => r.host.id))
  return rows.map((r) => ({ ...r.host, host_group: r.host_group, certificate: certs.get(r.host.id) ?? null }))
}

export async function listSshHosts(ctx: Context, actor: Actor, input: CursorInput & { host_group_id?: string; query?: string }) {
  authorize(sshHostPolicy, actor, 'read', undefined)
  const h = schema.sshHosts
  const page = keyset(byName(h.name, h.id), input)
  const pattern = input.query?.trim() ? `%${input.query.trim().replace(/[\\%_]/g, '\\$&')}%` : null
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, host: h, host_group: { id: schema.sshHostGroups.id, slug: schema.sshHostGroups.slug, name: schema.sshHostGroups.name } })
    .from(h)
    .innerJoin(schema.sshHostGroups, eq(schema.sshHostGroups.id, h.host_group_id))
    .where(and(input.host_group_id ? eq(h.host_group_id, input.host_group_id) : undefined, pattern ? or(ilike(h.name, pattern), sql`array_to_string(${h.hostnames}, ' ') ilike ${pattern}`) : undefined, page.where))
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  return { rows: await withCertificates(ctx.db, result.rows), next_cursor: result.next_cursor }
}

export async function getSshHost(ctx: Context, actor: Actor, id: string): Promise<SshHostListRow> {
  authorize(sshHostPolicy, actor, 'read', undefined)
  const [row] = await ctx.db
    .select({ host: schema.sshHosts, host_group: { id: schema.sshHostGroups.id, slug: schema.sshHostGroups.slug, name: schema.sshHostGroups.name } })
    .from(schema.sshHosts)
    .innerJoin(schema.sshHostGroups, eq(schema.sshHostGroups.id, schema.sshHosts.host_group_id))
    .where(eq(schema.sshHosts.id, id))
  if (!row) throw new NotFoundError('Host not found')
  return (await withCertificates(ctx.db, [row]))[0]!
}

