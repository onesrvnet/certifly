import { type Executor, schema } from '@certifly/db'
import type { EncryptedKeyRecord, GeneratedKey, KeyAlgorithm, Signer } from '@certifly/keyvault'
import { eq } from 'drizzle-orm'
import { recordEvent, systemEvent, withTransaction } from './audit'
import type { Context } from './context'

export type CaKeyRow = typeof schema.caKeys.$inferSelect

/**
 * The AAD both envelope layers are bound to. Naming the CA and the key row means a record
 * copied into another row (or another CA) no longer decrypts.
 */
export const caKeyBinding = (ca_id: string, key_id: string) => `ca_key:${ca_id}:${key_id}`

export function keyRecord(row: CaKeyRow): EncryptedKeyRecord {
  return {
    alg: row.alg,
    kek_id: row.kek_id,
    wrapped_dek: row.wrapped_dek,
    dek_iv: row.dek_iv,
    dek_tag: row.dek_tag,
    ciphertext: row.ciphertext,
    iv: row.iv,
    tag: row.tag,
  }
}

export interface NewCaKey {
  key_id: string
  generated: GeneratedKey
  signer: Signer
}

/** A fresh key for a CA, generated inside the key provider. The row is stored with `insertCaKey`. */
export async function generateCaKey(ctx: Context, ca_id: string, algorithm: KeyAlgorithm): Promise<NewCaKey> {
  const key_id = crypto.randomUUID()
  const binding = caKeyBinding(ca_id, key_id)
  const generated = await ctx.keys.generate(algorithm, binding)
  return { key_id, generated, signer: ctx.keys.signer(generated.record, binding, algorithm) }
}

export async function insertCaKey(db: Executor, ca_id: string, key: NewCaKey): Promise<CaKeyRow> {
  const { record, algorithm, public_key_spki } = key.generated
  const [row] = await db
    .insert(schema.caKeys)
    .values({ id: key.key_id, ca_id, key_source: 'local', algorithm, public_key_spki, ...record })
    .returning()
  return row!
}

/** Signs with a stored CA key. The key is decrypted only for each signature, inside the provider. */
export function caSigner(ctx: Context, row: CaKeyRow): Signer {
  return ctx.keys.signer(keyRecord(row), caKeyBinding(row.ca_id, row.id), row.algorithm as KeyAlgorithm)
}

/**
 * Re-wrap every CA key whose DEK is still wrapped under an older master key, so that
 * `CERTIFLY_MASTER_KEY_PREVIOUS` can be dropped afterwards. Only the wrapped DEK changes; the
 * key ciphertext stays as it is. Safe to run again: rows already current are skipped.
 */
export async function rewrapCaKeys(ctx: Context): Promise<{ rewrapped: number }> {
  const keys = ctx.keys
  if (!keys.needsRewrap || !keys.rewrap) return { rewrapped: 0 }
  const rows = await ctx.db.select().from(schema.caKeys)
  let rewrapped = 0
  for (const candidate of rows) {
    if (!(await keys.needsRewrap(keyRecord(candidate)))) continue
    await withTransaction(ctx, async (tx) => {
      const [row] = await tx.select().from(schema.caKeys).where(eq(schema.caKeys.id, candidate.id)).for('update')
      if (!row || !(await keys.needsRewrap!(keyRecord(row)))) return
      const next = await keys.rewrap!(keyRecord(row), caKeyBinding(row.ca_id, row.id))
      await tx
        .update(schema.caKeys)
        .set({ kek_id: next.kek_id, wrapped_dek: next.wrapped_dek, dek_iv: next.dek_iv, dek_tag: next.dek_tag })
        .where(eq(schema.caKeys.id, row.id))
      await recordEvent(ctx, systemEvent('ca_keys.rewrap', { type: 'ca_key', id: row.id }, { ca_id: row.ca_id, kek_id: next.kek_id }), tx)
      rewrapped++
    })
  }
  return { rewrapped }
}
