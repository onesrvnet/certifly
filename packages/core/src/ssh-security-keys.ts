import { randomBytes } from 'node:crypto'
import { type Executor, schema } from '@certifly/db'
import { PkiError, verifyFidoAttestation } from '@certifly/pki'
import { and, asc, count, desc, eq, gt, isNull, sql } from 'drizzle-orm'
import { alias } from 'drizzle-orm/pg-core'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import { userCode } from './cli-auth'
import type { Context } from './context'
import { AppError, AuthorizationError, ConflictError, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshSecurityKeyPolicy } from './policies'
import { parseSubmittedKey, plainKeyLine, revokeSshCertificatesIn } from './ssh-certificates'
import { stripControlCharacters } from './text'

/*
 * Security keys (YubiKeys) people register for SSH. The CLI asks for a challenge, makes the key
 * on the YubiKey with it and uploads the public key with its attestation; the person approves
 * it in the browser with a fresh confirmation. Host groups that require a security key then
 * sign only these keys, so a CLI token alone, with some other YubiKey, is not enough.
 */

export const SECURITY_KEY_ENROLLMENT_TTL_MS = 10 * 60 * 1000
export const SECURITY_KEY_POLL_INTERVAL_SECONDS = 3

export type SshSecurityKeyRow = typeof schema.sshSecurityKeys.$inferSelect
export type SshSecurityKeyEnrollmentRow = typeof schema.sshSecurityKeyEnrollments.$inferSelect
export type SshSecurityKeyListRow = SshSecurityKeyRow & {
  revoked_by: { id: string; name: string } | null
  /** Certificates for this key that are still valid. */
  active_certificates: number
}

const keySubject = (id: string) => ({ type: 'ssh_security_key', id })
const enrollmentSubject = (id: string) => ({ type: 'ssh_security_key_enrollment', id })

/** Yubico models by AAGUID (from Yubico's published list), for display only. */
const MODELS: Record<string, string> = {
  cb69481e8ff7403993ec0a2729a154a8: 'YubiKey 5 Series',
  ee882879721c491397753dfcce97072a: 'YubiKey 5 Series',
  fa2b99dc9e3942578f924a30d23c4118: 'YubiKey 5 Series with NFC',
  '2fc0579f811347eab116bb5a8db9202a': 'YubiKey 5 Series with NFC',
  c5ef55ffad9a4b9fb580adebafe026d0: 'YubiKey 5Ci',
  '73bb0cd4e50249b89c6fb59445bf720b': 'YubiKey 5 FIPS Series',
  c1f9a0bc1dd2404ab27f8e29047a43fd: 'YubiKey 5 FIPS Series with NFC',
  d8522d9f575b486688a9ba99fa02f35b: 'YubiKey Bio Series',
  f8a011f38c0a4d15800617111f9edc7d: 'Security Key by Yubico',
  b92c3f9ac0144056887f140a2501163b: 'Security Key by Yubico',
  '149a20218ef6413396b881f8d5b7f1f5': 'Security Key NFC by Yubico',
  a4e9fc6d4cbe4758b8ba37598bb5bbaa: 'Security Key NFC by Yubico',
}

/** The model name for a key's AAGUID: a known Yubico model, "YubiKey" for other attested ones, else null. */
export function securityKeyModel(aaguid: string | null, attested: boolean): string | null {
  if (!attested) return null
  return (aaguid && MODELS[aaguid]) || 'YubiKey'
}

const BASE64 = /^[A-Za-z0-9+/_-]+={0,2}$/

function decodeAttestation(value: string): Uint8Array {
  if (!BASE64.test(value) || value.length > 44 * 1024) throw new ValidationError('attestation is not valid base64', 'ssh_attestation_invalid')
  return new Uint8Array(Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64'))
}

function keyName(value: string | undefined, fallback: string): string {
  const name = stripControlCharacters(String(value ?? '')).trim()
  if (name.length > 100) throw new ValidationError('name must be at most 100 characters')
  return name || fallback
}

/** Uploading and polling belong to the CLI session that started the registration. */
function cliSession(actor: Actor): string {
  if (actor.kind !== 'cli' || !actor.cli_session_id) throw new AuthorizationError('Register security keys from the certifly CLI')
  return actor.cli_session_id
}

const expired = () => new NotFoundError('This registration has expired or does not exist', 'ssh_key_enrollment_expired')

async function assertNotRegistered(db: Executor, fingerprint: string) {
  const [taken] = await db.select({ id: schema.sshSecurityKeys.id }).from(schema.sshSecurityKeys).where(eq(schema.sshSecurityKeys.fingerprint, fingerprint))
  if (taken) throw new ConflictError('This security key is already registered, or was revoked. Create a new key on the YubiKey.', 'ssh_key_already_registered')
}

// ---------------------------------------------------------------------------------------------
// Registering

/** Start a registration from the CLI: a fresh challenge for `ssh-keygen -O challenge=`, valid ten minutes. */
export async function startSecurityKeyEnrollment(ctx: Context, actor: Actor) {
  const cli_session_id = cliSession(actor)
  const [session] = await ctx.db.select().from(schema.cliSessions).where(eq(schema.cliSessions.id, cli_session_id))
  if (!session) throw new AuthorizationError()
  const [row] = await ctx.db
    .insert(schema.sshSecurityKeyEnrollments)
    .values({
      user_id: actor.id,
      cli_session_id,
      challenge: new Uint8Array(randomBytes(32)),
      user_code: userCode(),
      machine_hostname: session.machine_hostname,
      machine_os: session.machine_os,
      expires_at: new Date(Date.now() + SECURITY_KEY_ENROLLMENT_TTL_MS),
    })
    .returning()
  return { enrollment: row!, browser_url: `${ctx.base_url.replace(/\/$/, '')}/cli/security-key/${row!.id}` }
}

async function cliEnrollment(db: Executor, actor: Actor, id: string): Promise<SshSecurityKeyEnrollmentRow> {
  const cli_session_id = cliSession(actor)
  const e = schema.sshSecurityKeyEnrollments
  const [row] = await db
    .select()
    .from(e)
    .where(and(eq(e.id, id), eq(e.user_id, actor.id), eq(e.cli_session_id, cli_session_id)))
  if (!row) throw expired()
  return row
}

export interface SubmitSecurityKeyInput {
  enrollment_id: string
  /** The `.pub` line ssh-keygen wrote. */
  public_key: string
  /** base64 of the file `ssh-keygen -O write-attestation=` wrote. */
  attestation?: string
  /** Defaults to the machine's host name. */
  name?: string
}

/**
 * Upload the key the CLI made with the registration's challenge. With an attestation from a
 * genuine YubiKey over that challenge, the key counts as attested; an attestation from another
 * maker's authenticator registers the key as not attested. Anything else wrong with the
 * attestation is refused. The key is not usable until the person approves it in the browser.
 */
export async function submitSecurityKeyEnrollment(ctx: Context, actor: Actor, input: SubmitSecurityKeyInput): Promise<SshSecurityKeyEnrollmentRow> {
  const enrollment = await cliEnrollment(ctx.db, actor, input.enrollment_id)
  if (enrollment.expires_at <= new Date()) throw expired()
  if (enrollment.submitted_at) throw new ConflictError('This registration already has a key', 'ssh_key_enrollment_used')
  const key = await parseSubmittedKey(input.public_key, { allowSk: true })
  if (!key.sk || !key.application) throw new ValidationError('Only security keys (ed25519-sk or ecdsa-sk) can be registered', 'ssh_key_type')
  await assertNotRegistered(ctx.db, key.fingerprint)

  let proof: { aaguid: string | null; attestation_subject: string | null; attested: boolean } = { aaguid: null, attestation_subject: null, attested: false }
  if (input.attestation !== undefined) {
    try {
      const result = await verifyFidoAttestation({ attestation: decodeAttestation(input.attestation), key, challenge: enrollment.challenge })
      proof = { aaguid: result.aaguid, attestation_subject: result.certificate_subject, attested: true }
    } catch (error) {
      if (!(error instanceof PkiError)) throw error
      if (error.code !== 'untrusted_ssh_attestation') throw new ValidationError(error.message, 'ssh_attestation_invalid')
    }
  }

  const e = schema.sshSecurityKeyEnrollments
  // Only the first upload lands, so two racing ones cannot swap the key under a shown code.
  const [row] = await ctx.db
    .update(e)
    .set({
      name: keyName(input.name, enrollment.machine_hostname),
      public_key: plainKeyLine(key),
      fingerprint: key.fingerprint,
      application: key.application,
      ...proof,
      submitted_at: new Date(),
    })
    .where(and(eq(e.id, enrollment.id), isNull(e.submitted_at)))
    .returning()
  if (!row) throw new ConflictError('This registration already has a key', 'ssh_key_enrollment_used')
  await recordEvent(ctx, eventFor(actor, 'ssh_security_key_enrollments.submit', enrollmentSubject(row.id), { fingerprint: key.fingerprint, attested: proof.attested, machine: row.machine_hostname }))
  return row
}

export type EnrollmentPollResult = { status: 'pending' } | { status: 'approved'; key: SshSecurityKeyRow }

/** The CLI asks whether the person approved. Errors: denied (403) and expired (410). */
export async function pollSecurityKeyEnrollment(ctx: Context, actor: Actor, id: string): Promise<EnrollmentPollResult> {
  const row = await cliEnrollment(ctx.db, actor, id)
  if (row.status === 'denied') throw new AppError(403, 'ssh_key_enrollment_denied', 'The registration was denied')
  if (row.status === 'approved' && row.ssh_security_key_id) {
    const [key] = await ctx.db.select().from(schema.sshSecurityKeys).where(eq(schema.sshSecurityKeys.id, row.ssh_security_key_id))
    if (key) return { status: 'approved', key }
  }
  if (row.expires_at <= new Date()) throw new AppError(410, 'ssh_key_enrollment_expired', 'This registration has expired')
  return { status: 'pending' }
}

/** For the approval page: the person's own uploaded, unexpired registration. */
export async function getSecurityKeyEnrollment(ctx: Context, actor: Actor, id: string): Promise<SshSecurityKeyEnrollmentRow> {
  const [row] = await ctx.db.select().from(schema.sshSecurityKeyEnrollments).where(eq(schema.sshSecurityKeyEnrollments.id, id))
  if (!row || row.user_id !== actor.id || !row.submitted_at || row.expires_at <= new Date()) throw expired()
  return row
}

/**
 * Approve or deny an uploaded key. Only the person's own browser session decides; approving
 * also needs a fresh confirmation (passkey, email code or provider), so a stolen CLI token
 * cannot register a key by itself.
 */
async function decide(ctx: Context, actor: Actor, id: string, status: 'approved' | 'denied') {
  if (status === 'approved') assertStepUp(actor)
  else if (actor.kind !== 'session') throw new AuthorizationError('Use a signed-in session for this')
  return withTransaction(ctx, async (tx) => {
    const e = schema.sshSecurityKeyEnrollments
    const [row] = await tx.select().from(e).where(eq(e.id, id)).for('update')
    if (!row || row.user_id !== actor.id || !row.submitted_at || row.expires_at <= new Date()) throw expired()
    if (row.status !== 'pending') return row
    if (status === 'denied') {
      const [updated] = await tx.update(e).set({ status }).where(eq(e.id, id)).returning()
      await recordEvent(ctx, eventFor(actor, 'ssh_security_key_enrollments.deny', enrollmentSubject(id), { fingerprint: row.fingerprint, user_code: row.user_code }), tx)
      return updated!
    }
    const [key] = await tx
      .insert(schema.sshSecurityKeys)
      .values({
        user_id: row.user_id,
        name: row.name!,
        public_key: row.public_key!,
        fingerprint: row.fingerprint!,
        application: row.application!,
        aaguid: row.aaguid,
        attestation_subject: row.attestation_subject,
        attested: row.attested,
        machine: row.machine_hostname,
      })
      .onConflictDoNothing({ target: schema.sshSecurityKeys.fingerprint })
      .returning()
    if (!key) throw new ConflictError('This security key is already registered, or was revoked. Create a new key on the YubiKey.', 'ssh_key_already_registered')
    const [updated] = await tx.update(e).set({ status, ssh_security_key_id: key.id }).where(eq(e.id, id)).returning()
    await recordEvent(
      ctx,
      eventFor(actor, 'ssh_security_keys.create', keySubject(key.id), { fingerprint: key.fingerprint, attested: key.attested, aaguid: key.aaguid, attestation_subject: key.attestation_subject, machine: key.machine }),
      tx,
    )
    return updated!
  })
}

export const approveSecurityKeyEnrollment = (ctx: Context, actor: Actor, id: string) => decide(ctx, actor, id, 'approved')
export const denySecurityKeyEnrollment = (ctx: Context, actor: Actor, id: string) => decide(ctx, actor, id, 'denied')

// ---------------------------------------------------------------------------------------------
// Listing, renaming, revoking

/** A person's keys: active ones first, then revoked ones, newest first within each. */
export async function listSshSecurityKeys(ctx: Context, actor: Actor, input: { user_id?: string } = {}): Promise<SshSecurityKeyListRow[]> {
  const user_id = input.user_id ?? actor.id
  if (user_id !== actor.id && !sshSecurityKeyPolicy.can(actor, 'read', { user_id })) throw new NotFoundError('User not found')
  authorize(sshSecurityKeyPolicy, actor, 'read', { user_id })
  const k = schema.sshSecurityKeys
  const c = schema.sshCertificates
  const revoker = alias(schema.users, 'revoker')
  const [rows, certs] = await Promise.all([
    ctx.db
      .select({ key: k, revoked_by: { id: revoker.id, name: revoker.name } })
      .from(k)
      .leftJoin(revoker, eq(revoker.id, k.revoked_by_user_id))
      .where(eq(k.user_id, user_id))
      .orderBy(sql`${k.revoked_at} is not null`, desc(k.created_at), asc(k.id)),
    ctx.db
      .select({ fingerprint: c.fingerprint, n: count() })
      .from(c)
      .where(and(eq(c.kind, 'user'), eq(c.user_id, user_id), isNull(c.revoked_at), gt(c.valid_before, new Date())))
      .groupBy(c.fingerprint),
  ])
  const active = new Map(certs.map((r) => [r.fingerprint, r.n]))
  return rows.map((r) => ({ ...r.key, revoked_by: r.revoked_by?.id ? r.revoked_by : null, active_certificates: r.key.revoked_at ? 0 : (active.get(r.key.fingerprint) ?? 0) }))
}

async function findReadable(db: Executor, actor: Actor, id: string): Promise<SshSecurityKeyRow> {
  const [row] = await db.select().from(schema.sshSecurityKeys).where(eq(schema.sshSecurityKeys.id, id))
  if (!row || !sshSecurityKeyPolicy.can(actor, 'read', row)) throw new NotFoundError('Security key not found')
  return row
}

async function withDetails(db: Executor, key: SshSecurityKeyRow): Promise<SshSecurityKeyListRow> {
  const c = schema.sshCertificates
  const [[revoker], [certs]] = await Promise.all([
    key.revoked_by_user_id ? db.select({ id: schema.users.id, name: schema.users.name }).from(schema.users).where(eq(schema.users.id, key.revoked_by_user_id)) : Promise.resolve([]),
    key.revoked_at
      ? Promise.resolve([{ n: 0 }])
      : db
          .select({ n: count() })
          .from(c)
          .where(and(eq(c.kind, 'user'), eq(c.user_id, key.user_id), eq(c.fingerprint, key.fingerprint), isNull(c.revoked_at), gt(c.valid_before, new Date()))),
  ])
  return { ...key, revoked_by: revoker ?? null, active_certificates: certs?.n ?? 0 }
}

export async function renameSshSecurityKey(ctx: Context, actor: Actor, id: string, name: string): Promise<SshSecurityKeyListRow> {
  const key = await findReadable(ctx.db, actor, id)
  authorize(sshSecurityKeyPolicy, actor, 'update', key)
  const clean = keyName(name, '')
  if (!clean) throw new ValidationError('Name cannot be empty')
  const [updated] = await ctx.db.update(schema.sshSecurityKeys).set({ name: clean, updated_at: new Date() }).where(eq(schema.sshSecurityKeys.id, key.id)).returning()
  await recordEvent(ctx, eventFor(actor, 'ssh_security_keys.update', keySubject(key.id), { name: clean }))
  return withDetails(ctx.db, updated!)
}

/**
 * Revoke a security key: it is never signed again, and every valid certificate for it goes on
 * its CA's revocation list in the same transaction. People revoke their own, admins anyone's;
 * both need a fresh confirmation.
 */
export async function revokeSshSecurityKey(ctx: Context, actor: Actor, id: string): Promise<SshSecurityKeyListRow> {
  const key = await findReadable(ctx.db, actor, id)
  authorize(sshSecurityKeyPolicy, actor, 'revoke', key)
  assertStepUp(actor)
  const updated = await withTransaction(ctx, async (tx) => {
    const k = schema.sshSecurityKeys
    const [row] = await tx.select().from(k).where(eq(k.id, id)).for('update')
    if (!row) throw new NotFoundError('Security key not found')
    if (row.revoked_at) return row
    const now = new Date()
    const [revoked] = await tx.update(k).set({ revoked_at: now, revoked_by_user_id: actor.id, updated_at: now }).where(eq(k.id, id)).returning()
    const c = schema.sshCertificates
    const certs = await tx
      .select({ id: c.id })
      .from(c)
      .where(and(eq(c.kind, 'user'), eq(c.user_id, row.user_id), eq(c.fingerprint, row.fingerprint), isNull(c.revoked_at), gt(c.valid_before, now)))
    const done = await revokeSshCertificatesIn(ctx, tx, actor, certs.map((r) => r.id), 'unspecified')
    await recordEvent(ctx, eventFor(actor, 'ssh_security_keys.revoke', keySubject(id), { user_id: row.user_id, fingerprint: row.fingerprint, certificates: done.length }), tx)
    return revoked!
  })
  return withDetails(ctx.db, updated)
}
