import { type Executor, schema, type Transaction } from '@certifly/db'
import { buildKrl, parseAuthorizedKey } from '@certifly/pki'
import { and, eq, gt, isNotNull, max } from 'drizzle-orm'
import type { Context } from './context'
import { NotFoundError } from './errors'

/**
 * Rebuild the OpenSSH revocation list of one SSH CA inside the caller's transaction. It names
 * every revoked certificate of the CA that has not expired yet (expired ones are refused by
 * sshd anyway), by serial. The version grows with every rebuild. Revocation calls this in the
 * same transaction, so the list a host fetches next always includes the revocation.
 */
export async function rebuildSshKrl(tx: Transaction, ssh_ca_id: string, now = new Date()): Promise<{ version: bigint; count: number }> {
  const [ca] = await tx.select().from(schema.sshCas).where(eq(schema.sshCas.id, ssh_ca_id)).for('update')
  if (!ca) throw new NotFoundError('SSH certificate authority not found')
  const c = schema.sshCertificates
  const revoked = await tx
    .select({ serial: c.serial })
    .from(c)
    .where(and(eq(c.ssh_ca_id, ssh_ca_id), isNotNull(c.revoked_at), gt(c.valid_before, now)))
  const [{ last } = { last: null }] = await tx.select({ last: max(schema.sshKrls.version) }).from(schema.sshKrls).where(eq(schema.sshKrls.ssh_ca_id, ssh_ca_id))
  const version = (last ?? 0n) + 1n
  const ca_key = await parseAuthorizedKey(ca.public_key)
  const krl = buildKrl({
    version,
    generated: now,
    comment: `certifly ${ca.slug}`,
    cas: [{ ca_key: ca_key.blob, serials: revoked.map((row) => row.serial) }],
  })
  const values = { version, krl, generated_at: now }
  await tx
    .insert(schema.sshKrls)
    .values({ ssh_ca_id, ...values })
    .onConflictDoUpdate({ target: schema.sshKrls.ssh_ca_id, set: values })
  return { version, count: revoked.length }
}

const publicFields = { krl: schema.sshKrls.krl, generated_at: schema.sshKrls.generated_at, version: schema.sshKrls.version }

/** The current revocation list of an SSH CA, by slug, for the public endpoint. */
export async function publicSshKrl(ctx: Context, slug: string) {
  const [row] = await ctx.db
    .select(publicFields)
    .from(schema.sshKrls)
    .innerJoin(schema.sshCas, eq(schema.sshCas.id, schema.sshKrls.ssh_ca_id))
    .where(eq(schema.sshCas.slug, slug))
  return row ?? null
}

/** The public key of an SSH CA as an authorized_keys line, by slug. */
export async function publicSshCaKey(ctx: Context, slug: string, db: Executor = ctx.db) {
  const [row] = await db.select({ public_key: schema.sshCas.public_key, updated_at: schema.sshCas.updated_at }).from(schema.sshCas).where(eq(schema.sshCas.slug, slug))
  return row ?? null
}
