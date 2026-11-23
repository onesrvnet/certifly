import { describe, expect, it } from 'vitest'
import { KEY_ALGORITHMS, KeyvaultError, LocalKeyProvider, hashFor, kekId, loadKeyvaultConfig, parseMasterKey, type EncryptedKeyRecord } from '../src/index'

const SESSION_SECRET = 'a-session-secret-that-is-long-enough-1234'
const KEK_A = 'a'.repeat(64)
const KEK_B = Buffer.alloc(32, 0xb7).toString('base64')
const BINDING = 'ca_key:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222'

async function provider(master_key = KEK_A, previous_master_keys?: string) {
  return new LocalKeyProvider(await loadKeyvaultConfig({ master_key, previous_master_keys, session_secret: SESSION_SECRET }))
}

function flip(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes)
  out[0]! ^= 0x01
  return out
}

async function expectCode(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toBeInstanceOf(KeyvaultError)
  await expect(promise).rejects.toMatchObject({ code })
}

async function verify(spki: Uint8Array, algorithm: (typeof KEY_ALGORITHMS)[number], data: Uint8Array, signature: Uint8Array) {
  if (algorithm === 'ed25519') {
    const edKey = await crypto.subtle.importKey('spki', new Uint8Array(spki), { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify({ name: 'Ed25519' }, edKey, new Uint8Array(signature), new Uint8Array(data))
  }
  const hash = hashFor(algorithm)
  const ec = algorithm.startsWith('ecdsa')
  const key = await crypto.subtle.importKey(
    'spki',
    new Uint8Array(spki),
    ec ? { name: 'ECDSA', namedCurve: algorithm === 'ecdsa-p256' ? 'P-256' : 'P-384' } : { name: 'RSASSA-PKCS1-v1_5', hash },
    false,
    ['verify'],
  )
  return crypto.subtle.verify(ec ? { name: 'ECDSA', hash } : { name: 'RSASSA-PKCS1-v1_5' }, key, new Uint8Array(signature), new Uint8Array(data))
}

describe('master key config', () => {
  it('accepts 32 bytes as hex, base64 or base64url', () => {
    expect(parseMasterKey(KEK_A, SESSION_SECRET).byteLength).toBe(32)
    expect(parseMasterKey(KEK_B, SESSION_SECRET).byteLength).toBe(32)
    expect(parseMasterKey(Buffer.alloc(32, 0xfb).toString('base64url'), SESSION_SECRET).byteLength).toBe(32)
  })

  it('refuses keys that are not 32 bytes', () => {
    expect(() => parseMasterKey('ab'.repeat(31), SESSION_SECRET)).toThrow(/32 bytes/)
    expect(() => parseMasterKey(Buffer.alloc(16).toString('base64'), SESSION_SECRET)).toThrow(/32 bytes/)
    expect(() => parseMasterKey('not a key!', SESSION_SECRET)).toThrow(/32 bytes/)
  })

  it('refuses a master key equal to the session secret', () => {
    expect(() => parseMasterKey(KEK_A, KEK_A)).toThrow(/session secret/)
    // The same bytes in another encoding are refused too.
    expect(() => parseMasterKey(Buffer.from(KEK_A, 'hex').toString('base64'), KEK_A)).toThrow(/session secret/)
  })

  it('derives a stable kek_id that is not a plain hash of the key', async () => {
    const raw = parseMasterKey(KEK_A, SESSION_SECRET)
    const id = await kekId(new Uint8Array(raw))
    expect(id).toMatch(/^[0-9a-f]{16}$/)
    expect(await kekId(new Uint8Array(raw))).toBe(id)
    const plain = Buffer.from(await crypto.subtle.digest('SHA-256', raw)).toString('hex')
    expect(plain.startsWith(id)).toBe(false)
  })
})

describe('envelope encryption', () => {
  it('round-trips: the stored key signs and its public key matches', async () => {
    const kv = await provider()
    const { record, public_key_spki } = await kv.generate('ecdsa-p256', BINDING)
    expect(record.alg).toBe('aes-256-gcm-envelope-v1')
    expect(record.wrapped_dek.byteLength).toBe(32)
    expect(await kv.publicKey(record, BINDING)).toEqual(public_key_spki)
    const data = new TextEncoder().encode('hello')
    expect(await verify(public_key_spki, 'ecdsa-p256', data, await kv.sign(record, BINDING, data, 'SHA-256'))).toBe(true)
  })

  it('fails with a different binding (AAD)', async () => {
    const kv = await provider()
    const { record } = await kv.generate('ecdsa-p256', BINDING)
    await expectCode(kv.publicKey(record, BINDING.replace('2222', '3333')), 'decrypt_failed')
  })

  it.each(['ciphertext', 'iv', 'tag', 'wrapped_dek', 'dek_iv', 'dek_tag'] as const)('fails when %s is tampered with', async (field) => {
    const kv = await provider()
    const { record } = await kv.generate('ecdsa-p256', BINDING)
    const tampered: EncryptedKeyRecord = { ...record, [field]: flip(record[field]) }
    await expectCode(kv.sign(tampered, BINDING, new Uint8Array([1]), 'SHA-256'), 'decrypt_failed')
  })

  it('refuses a malformed record', async () => {
    const kv = await provider()
    const { record } = await kv.generate('ecdsa-p256', BINDING)
    await expectCode(kv.publicKey({ ...record, iv: record.iv.subarray(0, 8) }, BINDING), 'invalid_record')
    await expectCode(kv.publicKey({ ...record, alg: 'other' }, BINDING), 'invalid_record')
  })

  it('fails cleanly for an unknown kek_id', async () => {
    const { record } = await (await provider(KEK_A)).generate('ecdsa-p256', BINDING)
    await expectCode((await provider(KEK_B)).publicKey(record, BINDING), 'unknown_kek')
  })
})

describe('master key rotation', () => {
  it('decrypts with a previous key, rewraps without touching the ciphertext, then works without the old key', async () => {
    const old = await provider(KEK_A)
    const { record, public_key_spki } = await old.generate('ecdsa-p384', BINDING)

    const rotated = await provider(KEK_B, KEK_A)
    expect(rotated.needsRewrap(record)).toBe(true)
    expect(await rotated.publicKey(record, BINDING)).toEqual(public_key_spki)

    const rewrapped = await rotated.rewrap(record, BINDING)
    expect(rewrapped.kek_id).not.toBe(record.kek_id)
    expect(rewrapped.ciphertext).toEqual(record.ciphertext)
    expect(rewrapped.iv).toEqual(record.iv)
    expect(rewrapped.tag).toEqual(record.tag)
    expect(rewrapped.wrapped_dek).not.toEqual(record.wrapped_dek)
    expect(rotated.needsRewrap(rewrapped)).toBe(false)

    const newOnly = await provider(KEK_B)
    expect(await newOnly.publicKey(rewrapped, BINDING)).toEqual(public_key_spki)
    await expectCode(newOnly.publicKey(record, BINDING), 'unknown_kek')
  })

  it('refuses to rewrap under the wrong binding', async () => {
    const { record } = await (await provider(KEK_A)).generate('ecdsa-p256', BINDING)
    await expectCode((await provider(KEK_B, KEK_A)).rewrap(record, 'ca_key:other'), 'decrypt_failed')
  })
})

describe('signing', () => {
  it.each(KEY_ALGORITHMS)('%s signatures verify with the public key', async (algorithm) => {
    const kv = await provider()
    const { record, public_key_spki } = await kv.generate(algorithm, BINDING)
    const data = crypto.getRandomValues(new Uint8Array(100))
    const direct = await kv.sign(record, BINDING, data, hashFor(algorithm))
    expect(await verify(public_key_spki, algorithm, data, direct)).toBe(true)
    const signer = kv.signer(record, BINDING, algorithm)
    expect(signer.hash).toBe(hashFor(algorithm))
    expect(await verify(public_key_spki, algorithm, data, await signer.sign(data))).toBe(true)
    expect(await kv.publicKey(record, BINDING)).toEqual(public_key_spki)
  }, 60_000)

  it('signs with RSA and SHA-512 when asked, and refuses SHA-512 for other keys', async () => {
    const kv = await provider()
    const { record, public_key_spki } = await kv.generate('rsa-2048', BINDING)
    const data = crypto.getRandomValues(new Uint8Array(64))
    const signer = kv.signer(record, BINDING, 'rsa-2048', { hash: 'SHA-512' })
    expect(signer.hash).toBe('SHA-512')
    const publicKey = await crypto.subtle.importKey('spki', new Uint8Array(public_key_spki), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, false, ['verify'])
    expect(await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, publicKey, new Uint8Array(await signer.sign(data)), data)).toBe(true)
    expect(() => kv.signer(record, BINDING, 'ecdsa-p256', { hash: 'SHA-512' })).toThrow(/cannot sign/)
  }, 60_000)

  it('imports an Ed25519 PKCS#8 key and derives its public key', async () => {
    const kv = await provider()
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const imported = await kv.importPkcs8(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)), BINDING)
    expect(imported.algorithm).toBe('ed25519')
    expect(imported.public_key_spki).toEqual(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)))
  })

  it('refuses a hash that does not belong to the key', async () => {
    const kv = await provider()
    const { record } = await kv.generate('ecdsa-p384', BINDING)
    await expectCode(kv.sign(record, BINDING, new Uint8Array([1]), 'SHA-256'), 'unsupported_algorithm')
  })

  it('catches a signer whose recorded algorithm does not match the stored key', async () => {
    const kv = await provider()
    const { record } = await kv.generate('ecdsa-p256', BINDING)
    await expectCode(kv.signer(record, BINDING, 'ecdsa-p384').sign(new Uint8Array([1])), 'key_mismatch')
  })

  it('imports a PKCS#8 fixture (test-only path)', async () => {
    const kv = await provider()
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
    const imported = await kv.importPkcs8(pkcs8, BINDING)
    expect(imported.algorithm).toBe('ecdsa-p384')
    expect(imported.public_key_spki).toEqual(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)))
  })

  it('has no way to export a private key', () => {
    const names = Object.getOwnPropertyNames(LocalKeyProvider.prototype)
    expect(names.filter((n) => /export|private|pkcs8/i.test(n) && n !== 'importPkcs8')).toEqual([])
  })
})
