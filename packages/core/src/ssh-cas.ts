import { type Executor, schema } from '@certifly/db'
import type { KeyAlgorithm, Signer } from '@certifly/keyvault'
import { formatAuthorizedKey, parsePrivateKeyForImport, PkiError, sshPublicKeyFromSpki } from '@certifly/pki'
import { count, eq } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import { assertStepUp } from './auth/sessions'
import type { Context } from './context'
import { byName, type CursorInput, keyset, paged } from './cursor'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, sshCaPolicy } from './policies'
import { rebuildSshKrl } from './ssh-krl'

export type SshCaRow = typeof schema.sshCas.$inferSelect
export type SshCaKeyRow = typeof schema.sshCaKeys.$inferSelect

/** Algorithms certifly generates SSH CA keys with. Imports also accept the other supported sizes. */
export const SSH_CA_ALGORITHMS = ['ed25519', 'ecdsa-p256', 'rsa-4096'] as const satisfies readonly KeyAlgorithm[]
const IMPORT_ALGORITHMS: readonly string[] = ['ed25519', 'ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096']

export const SSH_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/

const subjectOf = (id: string) => ({ type: 'ssh_ca', id })

/** The AAD both envelope layers of an SSH CA key are bound to. */
export const sshCaKeyBinding = (ca_id: string, key_id: string) => `ssh_ca_key:${ca_id}:${key_id}`

function checkText(name: string, field: string, max: number): string {
  const value = String(name ?? '').trim()
  if (!value || value.length > max) throw new ValidationError(`${field} must be 1 to ${max} characters`)
  return value
}

export function checkSlug(slug: string): string {
  if (!SSH_SLUG_PATTERN.test(slug)) throw new ValidationError('The slug must be lowercase letters, digits and hyphens (at most 64)', 'invalid_slug')
  return slug
}

function encrypted(row: SshCaKeyRow) {
  return { alg: row.alg, kek_id: row.kek_id, wrapped_dek: row.wrapped_dek, dek_iv: row.dek_iv, dek_tag: row.dek_tag, ciphertext: row.ciphertext, iv: row.iv, tag: row.tag }
}

/**
 * A signer for the CA's key. RSA keys sign with SHA-512 (`rsa-sha2-512`), as OpenSSH expects of
 * new certificates. The key is decrypted only inside the keyvault, for each signature.
 */
export function sshCaSigner(ctx: Context, key: SshCaKeyRow): Signer {
  const algorithm = key.algorithm as KeyAlgorithm
  return ctx.keys.signer(encrypted(key), sshCaKeyBinding(key.ssh_ca_id, key.id), algorithm, algorithm.startsWith('rsa-') ? { hash: 'SHA-512' } : undefined)
}

export interface CreateSshCaInput {
  name: string
  slug: string
  description?: string
  key_algorithm?: (typeof SSH_CA_ALGORITHMS)[number]
}

export interface ImportSshCaInput {
  name: string
  slug: string
  description?: string
  /** An unencrypted OpenSSH or PKCS#8 private key as text. */
  private_key: string
}

async function store(
  ctx: Context,
  actor: Actor,
  input: { name: string; slug: string; description: string; source: 'generated' | 'imported' },
  make: (ca_id: string, key_id: string) => Promise<{ record: Awaited<ReturnType<Context['keys']['generate']>>['record']; algorithm: string; public_key_spki: Uint8Array }>,
): Promise<SshCaRow> {
  const ca_id = crypto.randomUUID()
  const key_id = crypto.randomUUID()
  const generated = await make(ca_id, key_id)
  const key = await sshPublicKeyFromSpki(generated.public_key_spki, `certifly:${input.slug}`).catch((error) => {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code)
    throw error
  })
  try {
    return await withTransaction(ctx, async (tx) => {
      const [ca] = await tx
        .insert(schema.sshCas)
        .values({
          id: ca_id,
          slug: input.slug,
          name: input.name,
          description: input.description,
          key_algorithm: generated.algorithm,
          source: input.source,
          public_key: formatAuthorizedKey(key),
          fingerprint: key.fingerprint,
        })
        .returning()
      await tx.insert(schema.sshCaKeys).values({
        id: key_id,
        ssh_ca_id: ca_id,
        algorithm: generated.algorithm,
        public_key_spki: new Uint8Array(generated.public_key_spki),
        ...generated.record,
      })
      await rebuildSshKrl(tx, ca_id)
      await recordEvent(
        ctx,
        eventFor(actor, input.source === 'generated' ? 'ssh_cas.create' : 'ssh_cas.import', subjectOf(ca_id), {
          slug: input.slug,
          key_algorithm: generated.algorithm,
          fingerprint: key.fingerprint,
        }),
        tx,
      )
      return ca!
    })
  } catch (error) {
    if (isUniqueViolation(error, 'ssh_cas_slug_unique')) throw new ConflictError('Another SSH CA already uses this slug', 'slug_taken')
    throw error
  }
}

/** Create an SSH CA with a fresh key made inside the keyvault. Admins, interactive session, recent re-authentication. */
export async function createSshCa(ctx: Context, actor: Actor, input: CreateSshCaInput): Promise<SshCaRow> {
  authorize(sshCaPolicy, actor, 'create', undefined)
  assertStepUp(actor)
  const algorithm = input.key_algorithm ?? 'ed25519'
  if (!(SSH_CA_ALGORITHMS as readonly string[]).includes(algorithm)) throw new ValidationError(`The key algorithm must be one of ${SSH_CA_ALGORITHMS.join(', ')}`, 'unsupported_key')
  const slug = checkSlug(input.slug)
  const name = checkText(input.name, 'The name', 100)
  return store(ctx, actor, { name, slug, description: String(input.description ?? '').trim().slice(0, 1000), source: 'generated' }, async (ca_id, key_id) => {
    const generated = await ctx.keys.generate(algorithm, sshCaKeyBinding(ca_id, key_id))
    return generated
  })
}

/**
 * Import an existing SSH CA key. Only unencrypted keys are accepted; an encrypted one is
 * refused with a hint to remove the passphrase first. The key is stored encrypted like every
 * other CA key and cannot be read back. Admins, interactive session, recent re-authentication.
 */
export async function importSshCa(ctx: Context, actor: Actor, input: ImportSshCaInput): Promise<SshCaRow> {
  authorize(sshCaPolicy, actor, 'import', undefined)
  assertStepUp(actor)
  const slug = checkSlug(input.slug)
  const name = checkText(input.name, 'The name', 100)
  return store(ctx, actor, { name, slug, description: String(input.description ?? '').trim().slice(0, 1000), source: 'imported' }, async (ca_id, key_id) => {
    let parsed: ReturnType<typeof parsePrivateKeyForImport>
    try {
      parsed = parsePrivateKeyForImport(String(input.private_key ?? ''))
    } catch (error) {
      if (error instanceof PkiError) throw new ValidationError(error.message, error.code === 'ssh_key_encrypted' ? 'ssh_key_encrypted' : 'invalid_private_key')
      throw error
    }
    try {
      const imported = await ctx.keys.importPkcs8(parsed.pkcs8, sshCaKeyBinding(ca_id, key_id))
      if (!IMPORT_ALGORITHMS.includes(imported.algorithm)) throw new ValidationError('This key type cannot be an SSH CA', 'unsupported_key')
      return imported
    } catch (error) {
      if (error instanceof ValidationError) throw error
      if (error instanceof Error && error.name === 'KeyvaultError') throw new ValidationError('The private key is not valid', 'invalid_private_key')
      throw error
    } finally {
      parsed.pkcs8.fill(0)
    }
  })
}

export async function getSshCa(ctx: Context, actor: Actor, id: string): Promise<SshCaRow & { host_group_count: number }> {
  authorize(sshCaPolicy, actor, 'read', undefined)
  const [ca] = await ctx.db.select().from(schema.sshCas).where(eq(schema.sshCas.id, id))
  if (!ca) throw new NotFoundError('SSH certificate authority not found')
  const [row] = await ctx.db.select({ n: count() }).from(schema.sshHostGroups).where(eq(schema.sshHostGroups.ssh_ca_id, id))
  return { ...ca, host_group_count: row?.n ?? 0 }
}

export async function listSshCas(ctx: Context, actor: Actor, input: CursorInput) {
  authorize(sshCaPolicy, actor, 'read', undefined)
  const page = keyset(byName(schema.sshCas.name, schema.sshCas.id), input)
  const rows = await ctx.db
    .select({ cursor_keys: page.keys, ca: schema.sshCas })
    .from(schema.sshCas)
    .where(page.where)
    .orderBy(...page.orderBy)
    .limit(page.limit)
  const result = paged(rows, input.limit)
  const counts = await ctx.db
    .select({ ssh_ca_id: schema.sshHostGroups.ssh_ca_id, n: count() })
    .from(schema.sshHostGroups)
    .groupBy(schema.sshHostGroups.ssh_ca_id)
  const by = new Map(counts.map((c) => [c.ssh_ca_id, c.n]))
  return { rows: result.rows.map((row) => ({ ...row.ca, host_group_count: by.get(row.ca.id) ?? 0 })), next_cursor: result.next_cursor }
}

/** Change a CA's name or description. The slug and the key never change. */
export async function updateSshCa(ctx: Context, actor: Actor, id: string, input: { name?: string; description?: string }): Promise<SshCaRow> {
  authorize(sshCaPolicy, actor, 'update', undefined)
  const set: Partial<typeof schema.sshCas.$inferInsert> = {}
  if (input.name !== undefined) set.name = checkText(input.name, 'The name', 100)
  if (input.description !== undefined) set.description = String(input.description).trim().slice(0, 1000)
  const [row] = Object.keys(set).length
    ? await ctx.db.update(schema.sshCas).set(set).where(eq(schema.sshCas.id, id)).returning()
    : await ctx.db.select().from(schema.sshCas).where(eq(schema.sshCas.id, id))
  if (!row) throw new NotFoundError('SSH certificate authority not found')
  if (Object.keys(set).length) await recordEvent(ctx, eventFor(actor, 'ssh_cas.update', subjectOf(id), { fields: Object.keys(set) }))
  return row
}

/** Delete a CA that nothing uses: no host groups and no certificates it signed. */
export async function deleteSshCa(ctx: Context, actor: Actor, id: string): Promise<void> {
  authorize(sshCaPolicy, actor, 'delete', undefined)
  await withTransaction(ctx, async (tx) => {
    const [ca] = await tx.select().from(schema.sshCas).where(eq(schema.sshCas.id, id)).for('update')
    if (!ca) throw new NotFoundError('SSH certificate authority not found')
    const [groups] = await tx.select({ n: count() }).from(schema.sshHostGroups).where(eq(schema.sshHostGroups.ssh_ca_id, id))
    const [certs] = await tx.select({ n: count() }).from(schema.sshCertificates).where(eq(schema.sshCertificates.ssh_ca_id, id))
    if ((groups?.n ?? 0) > 0 || (certs?.n ?? 0) > 0) throw new ConflictError('This CA still has host groups or certificates', 'ssh_ca_in_use')
    await tx.delete(schema.sshCas).where(eq(schema.sshCas.id, id))
    await recordEvent(ctx, eventFor(actor, 'ssh_cas.delete', subjectOf(id), { slug: ca.slug }), tx)
  })
}

/** The key row of a CA, for signing. */
export async function loadSshCaKey(db: Executor, ssh_ca_id: string): Promise<SshCaKeyRow> {
  const [key] = await db.select().from(schema.sshCaKeys).where(eq(schema.sshCaKeys.ssh_ca_id, ssh_ca_id))
  if (!key) throw new NotFoundError('SSH certificate authority not found')
  return key
}
