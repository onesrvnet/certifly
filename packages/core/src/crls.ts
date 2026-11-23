import { type Executor, schema, type Transaction } from '@certifly/db'
import { buildCrl, PkiError } from '@certifly/pki'
import { and, desc, eq, inArray, isNotNull, isNull, lte, max, ne, or, sql } from 'drizzle-orm'
import { recordEvent, systemEvent, withTransaction } from './audit'
import { caSigner } from './ca-keys'
import type { Context } from './context'
import { AppError, ConflictError } from './errors'

export type CrlRow = typeof schema.crls.$inferSelect

const HOUR_MS = 60 * 60 * 1000

/** CAs whose CRL is published: everything with an installed certificate, disabled ones included. */
const PUBLISHING = ['active', 'disabled', 'expired'] as const

const subjectOf = (id: string) => ({ type: 'certificate_authority', id })

/**
 * Whether a CA key still needs a CRL: it has a certificate that is still valid (so it can sign
 * one), and it is the CA's active key or signed a certificate that has not expired yet. Correlated
 * with `ca_keys` and `certificate_authorities` in the outer query.
 */
function liveKey(now: Date) {
  const k = schema.caKeys
  const v = schema.caCertificates
  const c = schema.certificates
  const at = sql`${now.toISOString()}::timestamptz`
  return sql`(
    exists (select 1 from ${v} where ${v.key_id} = ${k.id} and ${v.not_after} > ${at})
    and (
      ${k.id} = ${schema.certificateAuthorities.active_key_id}
      or exists (select 1 from ${c} inner join ${v} on ${v.id} = ${c.ca_cert_id} where ${v.key_id} = ${k.id} and ${c.not_after} > ${at})
      or exists (select 1 from ${v} where ${v.issuer_key_id} = ${k.id} and ${v.ca_id} <> ${k.ca_id} and ${v.not_after} > ${at})
    )
  )`
}

/**
 * Build and store a new CRL for one key of a CA (the active key unless `key_id` says otherwise),
 * inside the caller's transaction. Each key's CRL is signed by that key and names the newest
 * certificate of that key as issuer, so it verifies for exactly the certificates the key signed.
 * It lists what that key signed and revoked that has not expired yet: subordinate CA
 * certificates and leaf certificates. The CA row is locked (`SELECT … FOR UPDATE`) while the
 * number is taken, so two builders never reuse one; numbers grow across all of a CA's CRLs
 * (RFC 5280 §5.2.3).
 */
export async function publishCrl(ctx: Context, tx: Transaction, ca_id: string, options: { key_id?: string; now?: Date } = {}): Promise<CrlRow> {
  const now = options.now ?? new Date()
  const [ca] = await tx.select().from(schema.certificateAuthorities).where(eq(schema.certificateAuthorities.id, ca_id)).for('update')
  if (!ca?.active_cert_id || !ca.active_key_id) throw new ConflictError('The CA has no certificate yet', 'ca_not_active')
  const key_id = options.key_id ?? ca.active_key_id
  const [key] = await tx.select().from(schema.caKeys).where(and(eq(schema.caKeys.id, key_id), eq(schema.caKeys.ca_id, ca_id)))
  const [cert] = await tx
    .select()
    .from(schema.caCertificates)
    .where(and(eq(schema.caCertificates.ca_id, ca_id), eq(schema.caCertificates.key_id, key_id)))
    .orderBy(desc(schema.caCertificates.version))
    .limit(1)
  if (!key || !cert) throw new ConflictError('This CA key has no certificate', 'ca_not_active')
  const [{ last } = { last: null }] = await tx.select({ last: max(schema.crls.crl_number) }).from(schema.crls).where(eq(schema.crls.ca_id, ca_id))

  const v = schema.caCertificates
  const c = schema.certificates
  const children = await tx
    .select({ serial: v.serial, revoked_at: v.revoked_at, reason: v.revocation_reason })
    .from(v)
    .where(
      and(
        eq(v.issuer_ca_id, ca_id),
        eq(v.issuer_key_id, key_id),
        // A root's own certificates name it as their issuer; they never belong on its CRL.
        ne(v.ca_id, ca_id),
        isNotNull(v.revoked_at),
        sql`${v.not_after} > ${now.toISOString()}::timestamptz`,
      ),
    )
  const leaves = await tx
    .select({ serial: c.serial, revoked_at: c.revoked_at, reason: c.revocation_reason })
    .from(c)
    .innerJoin(v, eq(v.id, c.ca_cert_id))
    .where(and(eq(c.ca_id, ca_id), eq(v.key_id, key_id), isNotNull(c.revoked_at), sql`${c.not_after} > ${now.toISOString()}::timestamptz`))

  const crl_number = (last ?? BigInt(0)) + BigInt(1)
  const built = await buildCrl({
    issuer_certificate: cert.certificate_der,
    signer: caSigner(ctx, key),
    crl_number,
    this_update: now,
    next_update: new Date(now.getTime() + ca.crl_validity_hours * HOUR_MS),
    entries: [...children, ...leaves].map((entry) => ({ serial: entry.serial, revoked_at: entry.revoked_at!, reason: entry.reason ?? undefined })),
  })
  const values = { crl_number, this_update: built.this_update, next_update: built.next_update, crl_der: built.der }
  const [row] = await tx
    .insert(schema.crls)
    .values({ ca_id, key_id, ...values })
    .onConflictDoUpdate({ target: [schema.crls.ca_id, schema.crls.key_id], set: values })
    .returning()
  return row!
}

/** A failure as it may go into the audit log and an alert: our own messages, never internals. */
function failureMessage(error: unknown): string {
  if (error instanceof PkiError || error instanceof AppError) return error.message
  return 'The CRL could not be built'
}

/** Records that a CRL could not be built, outside the failed transaction, so alerts can react. */
async function recordFailure(ctx: Context, ca_id: string, key_id: string, error: unknown) {
  console.error(`[crl] rebuilding the CRL of CA ${ca_id} (key ${key_id}) failed`, error instanceof PkiError ? error.message : error)
  try {
    await recordEvent(ctx, systemEvent('crls.publish_failed', subjectOf(ca_id), { key_id, error: failureMessage(error) }))
  } catch (recordError) {
    console.error('[crl] recording the failure failed', recordError)
  }
}

async function publishLogged(ctx: Context, ca_id: string, key_id: string, now: Date) {
  await withTransaction(ctx, async (tx) => {
    const crl = await publishCrl(ctx, tx, ca_id, { key_id, now })
    await recordEvent(ctx, systemEvent('crls.publish', subjectOf(ca_id), { key_id, crl_number: crl.crl_number.toString() }), tx)
  })
}

/** The keys of a CA that still publish a CRL (see `liveKey`). */
async function liveKeys(db: Executor, ca_id: string, now: Date): Promise<string[]> {
  const cas = schema.certificateAuthorities
  const rows = await db
    .select({ id: schema.caKeys.id })
    .from(schema.caKeys)
    .innerJoin(cas, eq(cas.id, schema.caKeys.ca_id))
    .where(and(eq(schema.caKeys.ca_id, ca_id), inArray(cas.status, [...PUBLISHING]), isNotNull(cas.active_cert_id), liveKey(now)))
  return rows.map((row) => row.id)
}

/**
 * Rebuild every CRL of one CA right away, e.g. after a revocation: one per key that still
 * signs a valid certificate. A key that fails does not stop the others; the job fails
 * afterwards so it is retried.
 */
export async function rebuildCaCrls(ctx: Context, ca_id: string, now = new Date()): Promise<{ rebuilt: number }> {
  let rebuilt = 0
  const failures: unknown[] = []
  for (const key_id of await liveKeys(ctx.db, ca_id, now)) {
    try {
      await publishLogged(ctx, ca_id, key_id, now)
      rebuilt++
    } catch (error) {
      await recordFailure(ctx, ca_id, key_id, error)
      failures.push(error)
    }
  }
  if (failures.length) throw new Error(`${failures.length} CRL rebuild(s) failed`)
  return { rebuilt }
}

/**
 * The scheduled CRL job: rebuild every CRL that enters its overlap window
 * (`next_update - crl_overlap_hours <= now`), so relying parties always find a fresh one before
 * the old one runs out, and mark CAs whose certificate has run out as expired. Every key with
 * certificates still valid keeps its CRL, so an old key's CRL lives on after a new-key renewal
 * until the last certificate it signed has expired. A CRL that fails does not stop the others;
 * the job fails afterwards so it is retried.
 */
export async function rebuildDueCrls(ctx: Context, now = new Date()): Promise<{ rebuilt: number; expired: number }> {
  const cas = schema.certificateAuthorities
  const expired = await withTransaction(ctx, async (tx) => {
    const rows = await tx
      .update(cas)
      .set({ status: 'expired' })
      .where(and(eq(cas.status, 'active'), lte(cas.not_after, now)))
      .returning({ id: cas.id })
    for (const row of rows) await recordEvent(ctx, systemEvent('certificate_authorities.expire', subjectOf(row.id)), tx)
    return rows.length
  })

  const due = await ctx.db
    .select({ ca_id: schema.caKeys.ca_id, key_id: schema.caKeys.id })
    .from(schema.caKeys)
    .innerJoin(cas, eq(cas.id, schema.caKeys.ca_id))
    .leftJoin(schema.crls, and(eq(schema.crls.ca_id, schema.caKeys.ca_id), eq(schema.crls.key_id, schema.caKeys.id)))
    .where(
      and(
        inArray(cas.status, [...PUBLISHING]),
        isNotNull(cas.active_cert_id),
        liveKey(now),
        or(isNull(schema.crls.ca_id), sql`${schema.crls.next_update} - make_interval(hours => ${cas.crl_overlap_hours}) <= ${now.toISOString()}::timestamptz`),
      ),
    )

  let rebuilt = 0
  const failures: unknown[] = []
  for (const { ca_id, key_id } of due) {
    try {
      await publishLogged(ctx, ca_id, key_id, now)
      rebuilt++
    } catch (error) {
      await recordFailure(ctx, ca_id, key_id, error)
      failures.push(error)
    }
  }
  if (failures.length) throw new Error(`${failures.length} CRL rebuild(s) failed`)
  return { rebuilt, expired }
}

const crlFields = { crl_der: schema.crls.crl_der, this_update: schema.crls.this_update, next_update: schema.crls.next_update }

/** The CRL of a CA's active key, by slug, for the public endpoint. Null when there is none. */
export async function publicCrl(ctx: Context, slug: string) {
  const cas = schema.certificateAuthorities
  const [row] = await ctx.db
    .select(crlFields)
    .from(schema.crls)
    .innerJoin(cas, and(eq(cas.id, schema.crls.ca_id), eq(cas.active_key_id, schema.crls.key_id)))
    .where(and(eq(cas.slug, slug), inArray(cas.status, [...PUBLISHING])))
  return row ?? null
}

/**
 * The CRL of one key of a CA, for the key-specific URL embedded in the certificates that key
 * signed. It stays right for them after the CA moves on to a new key.
 */
export async function publicKeyCrl(ctx: Context, slug: string, key_id: string) {
  const cas = schema.certificateAuthorities
  const [row] = await ctx.db
    .select(crlFields)
    .from(schema.crls)
    .innerJoin(cas, eq(cas.id, schema.crls.ca_id))
    .where(and(eq(cas.slug, slug), eq(schema.crls.key_id, key_id), inArray(cas.status, [...PUBLISHING])))
  return row ?? null
}
