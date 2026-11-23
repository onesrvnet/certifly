import { bytesEqual, fromBase64, fromHex, toHex, wipe } from './bytes'
import { KeyvaultError } from './errors'

const KEK_BYTES = 32
const KEK_ID_INFO = new TextEncoder().encode('certifly:keyvault:kek-id')

export interface KeyvaultConfigInput {
  /** The current master key (KEK): 32 bytes as hex or base64. */
  master_key: string
  /** Older master keys, accepted to unwrap only. A string may list several, comma or space separated. */
  previous_master_keys?: string | readonly string[]
  /** The session secret (`SECRET_KEY`). The master key must differ from it. */
  session_secret: string
}

/**
 * Parsed master keys. The KEKs are held as non-extractable CryptoKeys; their raw bytes are wiped
 * as soon as they are imported.
 */
export class KeyvaultConfig {
  readonly current_kek_id: string
  readonly #keks: ReadonlyMap<string, CryptoKey>

  /** Use `loadKeyvaultConfig`. */
  constructor(current_kek_id: string, keks: ReadonlyMap<string, CryptoKey>) {
    this.current_kek_id = current_kek_id
    this.#keks = keks
  }

  get kek_ids(): string[] {
    return [...this.#keks.keys()]
  }

  /** @internal */
  kek(kek_id: string): CryptoKey | undefined {
    return this.#keks.get(kek_id)
  }

  /** @internal */
  currentKek(): CryptoKey {
    return this.#keks.get(this.current_kek_id)!
  }
}

/**
 * Decodes a master key from hex (64 digits) or base64/base64url. Refuses anything that is not
 * exactly 32 bytes, and a key equal to the session secret: one leaked secret must not open both
 * the sessions and the CA keys. The caller owns the returned bytes and should wipe them.
 */
export function parseMasterKey(value: string, session_secret: string): Uint8Array<ArrayBuffer> {
  const text = value.trim()
  const bytes = (text.length === KEK_BYTES * 2 ? fromHex(text) : null) ?? fromBase64(text)
  if (!bytes || bytes.byteLength !== KEK_BYTES) {
    if (bytes) wipe(bytes)
    throw new KeyvaultError('invalid_config', 'The master key must be 32 bytes, as hex or base64')
  }
  if (sameAsSessionSecret(text, bytes, session_secret)) {
    wipe(bytes)
    throw new KeyvaultError('invalid_config', 'The master key must differ from the session secret')
  }
  return bytes
}

function sameAsSessionSecret(text: string, bytes: Uint8Array, session_secret: string): boolean {
  const secret = session_secret.trim()
  if (!secret) return false
  if (text === secret) return true
  // Also catch the same 32 bytes written in another encoding, or used verbatim as the secret.
  const candidates = [new TextEncoder().encode(secret), fromHex(secret), fromBase64(secret)]
  return candidates.some((candidate) => candidate !== null && bytesEqual(candidate, bytes))
}

/**
 * A short, public identifier for a KEK: the first 8 bytes of SHA-256 over an HKDF output of the
 * key. Being a PRF output of a 256-bit key, it says nothing useful to someone guessing the key.
 */
export async function kekId(kek: Uint8Array<ArrayBuffer>): Promise<string> {
  const ikm = await crypto.subtle.importKey('raw', kek, 'HKDF', false, ['deriveBits'])
  const derived = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: KEK_ID_INFO },
    ikm,
    256,
  )
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', derived))
  return toHex(digest.subarray(0, 8))
}

function splitKeys(value: string | readonly string[] | undefined): string[] {
  if (value === undefined) return []
  const list = typeof value === 'string' ? value.split(/[\s,]+/) : [...value]
  return list.map((v) => v.trim()).filter(Boolean)
}

export async function loadKeyvaultConfig(input: KeyvaultConfigInput): Promise<KeyvaultConfig> {
  const keks = new Map<string, CryptoKey>()
  let current_kek_id = ''
  for (const [index, text] of [input.master_key, ...splitKeys(input.previous_master_keys)].entries()) {
    const raw = parseMasterKey(text, input.session_secret)
    try {
      const id = await kekId(raw)
      if (index === 0) current_kek_id = id
      if (!keks.has(id)) {
        keks.set(id, await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']))
      }
    } finally {
      wipe(raw)
    }
  }
  return new KeyvaultConfig(current_kek_id, keks)
}
