import { PkiError } from '../errors'
import { SshWriter } from './wire'

/** PROTOCOL.krl: the magic is "SSHKRL\n\0". */
const KRL_MAGIC = new Uint8Array([0x53, 0x53, 0x48, 0x4b, 0x52, 0x4c, 0x0a, 0x00])
const KRL_FORMAT_VERSION = 1
const SECTION_CERTIFICATES = 1
const SECTION_EXPLICIT_KEY = 2
const CERT_SERIAL_LIST = 0x20
const CERT_KEY_ID = 0x23

export interface KrlCaEntry {
  /** The CA public key blob the certificates were signed by. */
  ca_key: Uint8Array
  serials: readonly bigint[]
  /** Key ids, for certificates revoked by id rather than serial. */
  key_ids?: readonly string[]
}

export interface KrlParams {
  /** Increases with every change, so hosts can tell which list is newer. */
  version: bigint
  generated: Date
  comment?: string
  cas: readonly KrlCaEntry[]
  /** Public key blobs (plain keys) to revoke outright. */
  keys?: readonly Uint8Array[]
}

/**
 * An unsigned OpenSSH key revocation list. Serials are listed (sorted, de-duplicated), not
 * packed into ranges: certifly serials are random, so ranges would not shrink anything.
 */
export function buildKrl(params: KrlParams): Uint8Array<ArrayBuffer> {
  if (params.version < 0n) throw new PkiError('invalid_input', 'The KRL version must not be negative')
  const out = new SshWriter()
    .raw(KRL_MAGIC)
    .uint32(KRL_FORMAT_VERSION)
    .uint64(params.version)
    .uint64(BigInt(Math.floor(params.generated.getTime() / 1000)))
    .uint64(0n)
    .string(new Uint8Array(0))
    .string(params.comment ?? '')
  for (const ca of params.cas) {
    const serials = [...new Set(ca.serials)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    const keyIds = [...new Set(ca.key_ids ?? [])].sort()
    if (serials.length === 0 && keyIds.length === 0) continue
    const sub = new SshWriter().string(ca.ca_key).string(new Uint8Array(0))
    if (serials.length > 0) {
      const list = new SshWriter()
      for (const serial of serials) list.uint64(serial)
      sub.byte(CERT_SERIAL_LIST).string(list.toBytes())
    }
    if (keyIds.length > 0) {
      const list = new SshWriter()
      for (const id of keyIds) list.string(id)
      sub.byte(CERT_KEY_ID).string(list.toBytes())
    }
    out.byte(SECTION_CERTIFICATES).string(sub.toBytes())
  }
  const keys = [...(params.keys ?? [])]
  if (keys.length > 0) {
    const list = new SshWriter()
    for (const key of keys) list.string(key)
    out.byte(SECTION_EXPLICIT_KEY).string(list.toBytes())
  }
  return out.toBytes()
}
