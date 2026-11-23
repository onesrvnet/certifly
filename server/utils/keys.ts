import type { CaKeyProvider } from '@certifly/core/context'
import { type EncryptedKeyRecord, hashFor, type HashAlgorithm, type KeyAlgorithm, LocalKeyProvider, loadKeyvaultConfig, type Signer, type SignerOptions } from '@certifly/keyvault'

let provider: Promise<LocalKeyProvider> | undefined

/**
 * The CA key store, built from the master key(s) in the environment. Importing the keys into
 * WebCrypto is asynchronous, so this starts at boot (server/plugins/00.migrate.ts) and every
 * key operation waits for it.
 */
export function keyProviderReady(): Promise<LocalKeyProvider> {
  provider ??= (async () => {
    const config = env()
    const keyvault = await loadKeyvaultConfig({
      master_key: config.CERTIFLY_MASTER_KEY!,
      previous_master_keys: config.CERTIFLY_MASTER_KEY_PREVIOUS,
      session_secret: config.SECRET_KEY,
    })
    return new LocalKeyProvider(keyvault)
  })()
  return provider
}

/** A synchronous handle on the key store for the domain context; each call waits until it is loaded. */
export function deferredKeyProvider(): CaKeyProvider {
  return {
    generate: async (algorithm: KeyAlgorithm, binding: string) => (await keyProviderReady()).generate(algorithm, binding),
    sign: async (record: EncryptedKeyRecord, binding: string, data: Uint8Array, hash: HashAlgorithm) => (await keyProviderReady()).sign(record, binding, data, hash),
    publicKey: async (record: EncryptedKeyRecord, binding: string) => (await keyProviderReady()).publicKey(record, binding),
    signer(record: EncryptedKeyRecord, binding: string, algorithm: KeyAlgorithm, options?: SignerOptions): Signer {
      return Object.freeze({
        key_algorithm: algorithm,
        hash: options?.hash ?? hashFor(algorithm),
        sign: async (data: Uint8Array) => (await keyProviderReady()).signer(record, binding, algorithm, options).sign(data),
      })
    },
    importPkcs8: async (pkcs8: Uint8Array, binding: string) => (await keyProviderReady()).importPkcs8(pkcs8, binding),
    needsRewrap: async (record: EncryptedKeyRecord) => (await keyProviderReady()).needsRewrap(record),
    rewrap: async (record: EncryptedKeyRecord, binding: string) => (await keyProviderReady()).rewrap(record, binding),
  }
}
