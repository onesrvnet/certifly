import { bytes, toBase64 } from '../encoding'
import { PkiError } from '../errors'
import { isValidCidr, isValidDnsName, parseIp } from '../names'
import { certificateTypeFor, keyFieldsForCertificate, type SshPublicKey } from './keys'
import { SshWriter } from './wire'

/** User certificate extensions OpenSSH knows (PROTOCOL.certkeys). */
export const SSH_USER_EXTENSIONS = [
  'no-touch-required',
  'permit-X11-forwarding',
  'permit-agent-forwarding',
  'permit-port-forwarding',
  'permit-pty',
  'permit-user-rc',
] as const
export type SshUserExtension = (typeof SSH_USER_EXTENSIONS)[number]

export type SshCertificateType = 'user' | 'host'

/**
 * What the certificate builder needs from a CA key: the algorithm and a WebCrypto-format signer
 * (PKCS#1 v1.5 for RSA, r || s for ECDSA, raw for Ed25519). RSA keys must sign with SHA-512,
 * which is what `rsa-sha2-512` means. A keyvault `Signer` fits this shape.
 */
export interface SshCaSigner {
  key_algorithm: string
  hash?: string
  sign(data: Uint8Array): Promise<Uint8Array>
}

export interface SshCertificateParams {
  type: SshCertificateType
  /** The key being certified. */
  public_key: SshPublicKey
  /** The CA's public key, matching `signer`. */
  ca_key: SshPublicKey
  signer: SshCaSigner
  serial: bigint
  key_id: string
  /** User names for user certificates, host names for host certificates. */
  principals: readonly string[]
  valid_after: Date
  valid_before: Date
  /** Critical options. They only apply to user certificates. */
  force_command?: string | null
  source_address?: readonly string[] | null
  /** Extensions, user certificates only. */
  extensions?: readonly string[]
  /** Appended to the certificate line, as ssh-keygen does with the key's comment. */
  comment?: string
}

export interface SshCertificate {
  /** The `<type>-cert-v01@openssh.com AAAA… comment` line. */
  line: string
  blob: Uint8Array<ArrayBuffer>
  serial: bigint
  key_id: string
  principals: string[]
  valid_after: Date
  valid_before: Date
}

function bad(message: string): never {
  throw new PkiError('invalid_ssh_certificate', message)
}

/** Whether a user principal / local user name is acceptable inside a certificate. */
export function isValidSshPrincipal(value: string): boolean {
  return typeof value === 'string' && value.length > 0 && value.length <= 255 && !/[\s,\0*?!]/.test(value) && value === value.normalize('NFC')
}

const MAX_SERIAL = (1n << 64n) - 1n

/** OpenSSH checks source-address as a comma separated list of addresses and CIDRs. */
export function isValidSourceAddressList(list: readonly string[]): boolean {
  return list.length > 0 && list.every((item) => parseIp(item) !== null || isValidCidr(item))
}

function algorithmOfSigner(signer: SshCaSigner, ca_key: SshPublicKey): { name: string; encode: (raw: Uint8Array) => Uint8Array } {
  const alg = signer.key_algorithm
  if (ca_key.sk) bad('A security key cannot be a certificate authority')
  if (alg === 'ed25519') {
    if (ca_key.family !== 'ed25519') bad('The signer does not match the CA key')
    return { name: 'ssh-ed25519', encode: (raw) => raw }
  }
  if (alg === 'ecdsa-p256' || alg === 'ecdsa-p384') {
    const curve = alg === 'ecdsa-p256' ? 'nistp256' : 'nistp384'
    if (ca_key.family !== 'ecdsa' || ca_key.curve !== curve) bad('The signer does not match the CA key')
    return {
      name: `ecdsa-sha2-${curve}`,
      encode(raw) {
        const half = raw.byteLength / 2
        return new SshWriter().mpint(raw.subarray(0, half)).mpint(raw.subarray(half)).toBytes()
      },
    }
  }
  if (alg.startsWith('rsa-')) {
    if (ca_key.family !== 'rsa') bad('The signer does not match the CA key')
    if (signer.hash !== 'SHA-512') bad('RSA certificate authorities must sign with SHA-512')
    return { name: 'rsa-sha2-512', encode: (raw) => raw }
  }
  bad('Unsupported CA key algorithm')
}

/** Wraps a raw signature the way SSH carries it: string(type) string(blob). */
export function encodeSshSignature(name: string, blob: Uint8Array): Uint8Array<ArrayBuffer> {
  return new SshWriter().string(name).string(blob).toBytes()
}

export async function buildSshCertificate(params: SshCertificateParams): Promise<SshCertificate> {
  const { type, public_key, ca_key, signer } = params
  if (params.serial < 0n || params.serial > MAX_SERIAL) bad('The serial is out of range')
  if (params.key_id.length === 0 || params.key_id.length > 1024) bad('The key id is empty or too long')
  const after = Math.floor(params.valid_after.getTime() / 1000)
  const before = Math.floor(params.valid_before.getTime() / 1000)
  if (!(after >= 0) || !(before > after)) bad('The validity period is not valid')
  if (params.principals.length === 0) bad('A certificate needs at least one principal')
  if (new Set(params.principals).size !== params.principals.length) bad('Duplicate principals')
  for (const principal of params.principals) {
    if (type === 'user' ? !isValidSshPrincipal(principal) : !isValidHostPrincipal(principal)) bad(`Invalid principal: ${principal.slice(0, 64)}`)
  }

  const critical: Array<[string, Uint8Array]> = []
  if (params.force_command) {
    if (type !== 'user') bad('Critical options only apply to user certificates')
    critical.push(['force-command', new SshWriter().string(params.force_command).toBytes()])
  }
  if (params.source_address && params.source_address.length > 0) {
    if (type !== 'user') bad('Critical options only apply to user certificates')
    if (!isValidSourceAddressList(params.source_address)) bad('Invalid source address list')
    critical.push(['source-address', new SshWriter().string(params.source_address.join(',')).toBytes()])
  }
  const extensions = [...new Set(params.extensions ?? [])]
  if (extensions.length > 0 && type !== 'user') bad('Extensions only apply to user certificates')
  for (const name of extensions) if (!(SSH_USER_EXTENSIONS as readonly string[]).includes(name)) bad(`Unknown extension: ${name.slice(0, 64)}`)

  const sortByName = (a: [string, Uint8Array], b: [string, Uint8Array]) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)
  const options = new SshWriter()
  for (const [name, data] of critical.sort(sortByName)) options.string(name).string(data)
  const exts = new SshWriter()
  for (const name of [...extensions].sort()) exts.string(name).string(new Uint8Array(0))
  const principals = new SshWriter()
  for (const principal of params.principals) principals.string(principal)

  const nonce = crypto.getRandomValues(new Uint8Array(32))
  const signature = algorithmOfSigner(signer, ca_key)
  const body = new SshWriter()
    .string(certificateTypeFor(public_key.type))
    .string(nonce)
    .raw(keyFieldsForCertificate(public_key))
    .uint64(params.serial)
    .uint32(type === 'user' ? 1 : 2)
    .string(params.key_id)
    .string(principals.toBytes())
    .uint64(BigInt(after))
    .uint64(BigInt(before))
    .string(options.toBytes())
    .string(exts.toBytes())
    .string(new Uint8Array(0))
    .string(ca_key.blob)
    .toBytes()
  const raw = await signer.sign(body)
  const blob = new SshWriter().raw(body).string(encodeSshSignature(signature.name, signature.encode(bytes(raw)))).toBytes()
  const typeName = certificateTypeFor(public_key.type)
  const comment = params.comment ? ` ${params.comment}` : ''
  return {
    line: `${typeName} ${toBase64(blob)}${comment}`,
    blob,
    serial: params.serial,
    key_id: params.key_id,
    principals: [...params.principals],
    valid_after: new Date(after * 1000),
    valid_before: new Date(before * 1000),
  }
}

/** Host principals: DNS names, or wildcard patterns like `*.example.com`. */
export function isValidHostPrincipal(value: string): boolean {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) return false
  if (parseIp(value) !== null) return true
  const name = value.startsWith('*.') ? value.slice(2) : value
  return isValidDnsName(name.toLowerCase()) || /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(name)
}

/** A random 63-bit serial: positive, so tools that read it as signed 64-bit stay happy. */
export function generateSshSerial(): bigint {
  const raw = crypto.getRandomValues(new Uint8Array(8))
  raw[0]! &= 0x7f
  let value = 0n
  for (const b of raw) value = (value << 8n) | BigInt(b)
  return value === 0n ? 1n : value
}
