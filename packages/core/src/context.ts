import type { Database } from '@certifly/db'
import type { EncryptedKeyRecord, KeyProvider } from '@certifly/keyvault'
import type { EmitEvent } from './audit'
import type { EnqueueJob } from './jobs'
import type { Mailer } from './mailer'

/** Dependencies shared by all domain operations. */
export interface Context {
  db: Database
  mailer: Mailer
  /** Public base URL, used to build links in emails. */
  base_url: string
  /** Told about every audit event after it has been stored, e.g. to trigger alerts. */
  emit: EmitEvent
  /** Queue follow-up work (emails, cleanup) to run after the response, possibly in a worker. */
  enqueue: EnqueueJob
  /** The server's SECRET_KEY, e.g. to encrypt secrets stored in the database. */
  secret_key: string
  /** The server's SETUP_TOKEN: when set, the very first sign-in must present it. */
  setup_token?: string | null
  /** Holds and signs with CA private keys; core never sees key bytes. */
  keys: CaKeyProvider
  /**
   * Origin of the public CRL and CA certificate URLs (`PKI_BASE_URL`, else `URL`), no trailing
   * slash. These URLs get embedded in certificates, so it must stay stable.
   */
  pki_base_url: string
  /** Where ACME challenges are validated; ports 80 and 443 when left out. */
  acme?: { http01_port: number; tlsalpn01_port: number }
}

/**
 * A key provider that can also move records to the current master key, as `LocalKeyProvider`
 * can. Providers whose keys never leave an HSM have nothing to rewrap and leave these out.
 */
export interface CaKeyProvider extends KeyProvider {
  needsRewrap?(record: EncryptedKeyRecord): boolean | Promise<boolean>
  rewrap?(record: EncryptedKeyRecord, binding: string): Promise<EncryptedKeyRecord>
}
