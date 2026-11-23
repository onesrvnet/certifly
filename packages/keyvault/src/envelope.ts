import { copy, wipe } from './bytes'
import type { KeyvaultConfig } from './config'
import { KeyvaultError } from './errors'
import { ENVELOPE_ALG, type EncryptedKeyRecord } from './types'

const IV_BYTES = 12
const TAG_BYTES = 16
const DEK_BYTES = 32
const MAX_BINDING = 512

/** The AAD for both layers, so a record cannot be moved to another row and still decrypt. */
export function bindingBytes(binding: string): Uint8Array<ArrayBuffer> {
  if (typeof binding !== 'string' || binding.length === 0 || binding.length > MAX_BINDING) {
    throw new KeyvaultError('invalid_binding', 'The key binding must be a non-empty string')
  }
  return new TextEncoder().encode(binding)
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length))
}

/** AES-GCM output is ciphertext || tag; the record keeps them in separate columns. */
async function gcmEncrypt(key: CryptoKey, iv: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>, plaintext: Uint8Array<ArrayBuffer>) {
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_BYTES * 8 }, key, plaintext))
  return { ciphertext: sealed.slice(0, sealed.byteLength - TAG_BYTES), tag: sealed.slice(sealed.byteLength - TAG_BYTES) }
}

async function gcmDecrypt(key: CryptoKey, iv: Uint8Array, aad: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const sealed = new Uint8Array(ciphertext.byteLength + tag.byteLength)
  sealed.set(ciphertext)
  sealed.set(tag, ciphertext.byteLength)
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: copy(iv), additionalData: aad, tagLength: TAG_BYTES * 8 }, key, sealed))
  } catch {
    throw new KeyvaultError('decrypt_failed', 'The key record could not be decrypted')
  }
}

function importDek(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

function checkRecord(record: EncryptedKeyRecord): void {
  const ok =
    record &&
    record.alg === ENVELOPE_ALG &&
    typeof record.kek_id === 'string' &&
    [record.wrapped_dek, record.dek_iv, record.dek_tag, record.ciphertext, record.iv, record.tag].every((b) => b instanceof Uint8Array) &&
    record.wrapped_dek.byteLength === DEK_BYTES &&
    record.dek_iv.byteLength === IV_BYTES &&
    record.iv.byteLength === IV_BYTES &&
    record.dek_tag.byteLength === TAG_BYTES &&
    record.tag.byteLength === TAG_BYTES &&
    record.ciphertext.byteLength > 0
  if (!ok) throw new KeyvaultError('invalid_record', 'The key record is malformed')
}

async function wrapDek(config: KeyvaultConfig, dek: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>) {
  const dek_iv = randomBytes(IV_BYTES)
  const { ciphertext: wrapped_dek, tag: dek_tag } = await gcmEncrypt(config.currentKek(), dek_iv, aad, dek)
  return { kek_id: config.current_kek_id, wrapped_dek, dek_iv, dek_tag }
}

/** Returns the raw DEK; the caller must wipe it. */
async function unwrapDek(config: KeyvaultConfig, record: EncryptedKeyRecord, aad: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const kek = config.kek(record.kek_id)
  if (!kek) throw new KeyvaultError('unknown_kek', 'The key record was wrapped with a master key that is not configured')
  return gcmDecrypt(kek, record.dek_iv, aad, record.wrapped_dek, record.dek_tag)
}

/** Encrypts a PKCS#8 key under a fresh DEK. The caller still owns (and wipes) `pkcs8`. */
export async function seal(config: KeyvaultConfig, pkcs8: Uint8Array<ArrayBuffer>, binding: string): Promise<EncryptedKeyRecord> {
  const aad = bindingBytes(binding)
  const dek = randomBytes(DEK_BYTES)
  try {
    const iv = randomBytes(IV_BYTES)
    const { ciphertext, tag } = await gcmEncrypt(await importDek(dek), iv, aad, pkcs8)
    const wrapped = await wrapDek(config, dek, aad)
    return { alg: ENVELOPE_ALG, ...wrapped, ciphertext, iv, tag }
  } finally {
    wipe(dek)
  }
}

/** Decrypts the PKCS#8 key. Only for use inside this package; the caller must wipe the result. */
export async function open(config: KeyvaultConfig, record: EncryptedKeyRecord, binding: string): Promise<Uint8Array<ArrayBuffer>> {
  checkRecord(record)
  const aad = bindingBytes(binding)
  const dek = await unwrapDek(config, record, aad)
  try {
    return await gcmDecrypt(await importDek(dek), record.iv, aad, record.ciphertext, record.tag)
  } finally {
    wipe(dek)
  }
}

/**
 * Re-wraps the DEK under the current master key. The key ciphertext is left untouched, so
 * rotating the master key never re-encrypts private keys.
 */
export async function rewrap(config: KeyvaultConfig, record: EncryptedKeyRecord, binding: string): Promise<EncryptedKeyRecord> {
  checkRecord(record)
  const aad = bindingBytes(binding)
  const dek = await unwrapDek(config, record, aad)
  try {
    // The GCM tag on the old wrapping already proves the DEK is genuine, so the key itself
    // is never decrypted here.
    return { ...record, ...(await wrapDek(config, dek, aad)) }
  } finally {
    wipe(dek)
  }
}
