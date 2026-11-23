import { bytes, toBase64 } from '../encoding'
import { PkiError } from '../errors'
import { SshReader, SshWriter } from './wire'

export const SSH_KEY_TYPES = [
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ssh-rsa',
  'sk-ssh-ed25519@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com',
] as const
export type SshKeyType = (typeof SSH_KEY_TYPES)[number]

export type SshKeyFamily = 'ed25519' | 'ecdsa' | 'rsa'
export type SshCurve = 'nistp256' | 'nistp384'

export interface SshPublicKey {
  type: SshKeyType
  family: SshKeyFamily
  /** True for FIDO security keys (`sk-…`). */
  sk: boolean
  curve?: SshCurve
  /** Bits of the key: 256 for Ed25519, 256/384 for ECDSA, the modulus size for RSA. */
  bits: number
  /** FIDO application (`ssh:` by default), only for sk keys. */
  application?: string
  /** The wire blob that follows the base64 in an authorized_keys line. */
  blob: Uint8Array<ArrayBuffer>
  comment: string
  /** `SHA256:<base64 without padding>`, as OpenSSH prints it. */
  fingerprint: string
  /** Ed25519 public key, or the uncompressed EC point. */
  point?: Uint8Array<ArrayBuffer>
  rsa?: { e: Uint8Array<ArrayBuffer>; n: Uint8Array<ArrayBuffer> }
}

export interface ParseKeyOptions {
  /** Smallest RSA modulus accepted. */
  min_rsa_bits?: number
}

export const DEFAULT_MIN_RSA_BITS = 2048
const MAX_RSA_BITS = 8192

const CERT_TYPES: Record<SshKeyType, string> = {
  'ssh-ed25519': 'ssh-ed25519-cert-v01@openssh.com',
  'ecdsa-sha2-nistp256': 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
  'ecdsa-sha2-nistp384': 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
  'ssh-rsa': 'ssh-rsa-cert-v01@openssh.com',
  'sk-ssh-ed25519@openssh.com': 'sk-ssh-ed25519-cert-v01@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
}

export function certificateTypeFor(type: SshKeyType): string {
  return CERT_TYPES[type]
}

export function isSshKeyType(value: string): value is SshKeyType {
  return (SSH_KEY_TYPES as readonly string[]).includes(value)
}

function bad(message: string): never {
  throw new PkiError('invalid_ssh_key', message)
}

export async function sshFingerprint(blob: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(blob)))
  return `SHA256:${toBase64(digest).replace(/=+$/, '')}`
}

function fromBase64Strict(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) bad('The key is not valid base64')
  const binary = atob(text)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

const CURVE_BY_TYPE: Record<string, SshCurve | undefined> = {
  'ecdsa-sha2-nistp256': 'nistp256',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'nistp256',
  'ecdsa-sha2-nistp384': 'nistp384',
}

/** Parses the wire blob of a public key. The curve point is checked to lie on the curve. */
export async function parseSshPublicKeyBlob(blob: Uint8Array, comment = '', options: ParseKeyOptions = {}): Promise<SshPublicKey> {
  const reader = new SshReader(blob)
  const typeName = reader.text()
  if (!isSshKeyType(typeName)) {
    bad(`Unsupported key type: ${typeName.slice(0, 64)}`)
  }
  const type: SshKeyType = typeName
  const sk = type.startsWith('sk-')
  const key: SshPublicKey = {
    type,
    family: type.includes('ed25519') ? 'ed25519' : type.includes('ecdsa') ? 'ecdsa' : 'rsa',
    sk,
    bits: 0,
    blob: bytes(blob),
    comment,
    fingerprint: await sshFingerprint(blob),
  }
  if (key.family === 'ed25519') {
    const point = reader.string()
    if (point.byteLength !== 32) bad('An Ed25519 key must be 32 bytes')
    try {
      await crypto.subtle.importKey('raw', point, { name: 'Ed25519' }, true, ['verify'])
    } catch {
      bad('The Ed25519 key is malformed')
    }
    key.point = point
    key.bits = 256
  } else if (key.family === 'ecdsa') {
    const curve = reader.text()
    const expected = CURVE_BY_TYPE[type]
    if (curve !== expected) bad('The curve does not match the key type')
    const point = reader.string()
    try {
      await crypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: curve === 'nistp256' ? 'P-256' : 'P-384' }, true, ['verify'])
    } catch {
      bad('The ECDSA public key is not a point on its curve')
    }
    key.curve = expected
    key.point = point
    key.bits = curve === 'nistp256' ? 256 : 384
  } else {
    const e = reader.mpint()
    const n = reader.mpint()
    const bits = n.byteLength === 0 ? 0 : (n.byteLength - 1) * 8 + (32 - Math.clz32(n[0]!))
    const min = options.min_rsa_bits ?? DEFAULT_MIN_RSA_BITS
    if (bits < min) bad(`RSA keys must be at least ${min} bits`)
    if (bits > MAX_RSA_BITS) bad(`RSA keys must be at most ${MAX_RSA_BITS} bits`)
    if (n[n.byteLength - 1]! % 2 === 0) bad('The RSA modulus is even')
    if (e.byteLength === 0 || e.byteLength > 8 || e[e.byteLength - 1]! % 2 === 0) bad('The RSA exponent is invalid')
    key.rsa = { e, n }
    key.bits = bits
  }
  if (sk) {
    const application = reader.text()
    if (!application) bad('The security key has no application')
    key.application = application
  }
  if (!reader.done) bad('Unexpected data after the public key')
  return key
}

/** Parses an authorized_keys style line: `<type> <base64> [comment]`, with no options prefix. */
export async function parseAuthorizedKey(line: string, options: ParseKeyOptions = {}): Promise<SshPublicKey> {
  const trimmed = line.trim()
  if (trimmed.length === 0 || trimmed.length > 16384 || /[\r\n]/.test(trimmed)) bad('Expected a single public key line')
  const match = /^(\S+)[ \t]+(\S+)(?:[ \t]+(.*))?$/.exec(trimmed)
  if (!match) bad('Expected "<type> <key> [comment]"')
  const [, typeName, body, comment = ''] = match
  if (!isSshKeyType(typeName!)) bad(`Unsupported key type: ${typeName!.slice(0, 64)}`)
  const key = await parseSshPublicKeyBlob(fromBase64Strict(body!), comment, options)
  if (key.type !== typeName) bad('The key type does not match the key data')
  return key
}

/** The authorized_keys line for a key. Pass `comment` to override the parsed comment. */
export function formatAuthorizedKey(key: { type: string; blob: Uint8Array }, comment?: string): string {
  const text = comment === undefined ? ('comment' in key ? String((key as SshPublicKey).comment) : '') : comment
  return `${key.type} ${toBase64(key.blob)}${text ? ` ${text}` : ''}`
}

/** The fields of a public key as a certificate carries them: the blob without its type string. */
export function keyFieldsForCertificate(key: SshPublicKey): Uint8Array<ArrayBuffer> {
  const out = new SshWriter()
  if (key.family === 'ed25519') out.string(key.point!)
  else if (key.family === 'ecdsa') out.string(key.curve!).string(key.point!)
  else out.mpint(key.rsa!.e).mpint(key.rsa!.n)
  if (key.sk) out.string(key.application!)
  return out.toBytes()
}

/** An SSH public key from a SubjectPublicKeyInfo (Ed25519, ECDSA P-256/P-384 or RSA). */
export async function sshPublicKeyFromSpki(spki: Uint8Array, comment = '', options: ParseKeyOptions = {}): Promise<SshPublicKey> {
  const der = bytes(spki)
  const attempts: Array<[Algorithm | EcKeyImportParams | RsaHashedImportParams, 'ed25519' | 'p256' | 'p384' | 'rsa']> = [
    [{ name: 'Ed25519' }, 'ed25519'],
    [{ name: 'ECDSA', namedCurve: 'P-256' }, 'p256'],
    [{ name: 'ECDSA', namedCurve: 'P-384' }, 'p384'],
    [{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, 'rsa'],
  ]
  for (const [params, kind] of attempts) {
    let cryptoKey: CryptoKey
    try {
      cryptoKey = await crypto.subtle.importKey('spki', der, params, true, ['verify'])
    } catch {
      continue
    }
    const out = new SshWriter()
    if (kind === 'ed25519') {
      out.string('ssh-ed25519').string(new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey)))
    } else if (kind === 'rsa') {
      const jwk = await crypto.subtle.exportKey('jwk', cryptoKey)
      out.string('ssh-rsa').mpint(base64UrlDecode(jwk.e!)).mpint(base64UrlDecode(jwk.n!))
    } else {
      const curve = kind === 'p256' ? 'nistp256' : 'nistp384'
      out.string(`ecdsa-sha2-${curve}`).string(curve).string(new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey)))
    }
    return parseSshPublicKeyBlob(out.toBytes(), comment, options)
  }
  throw new PkiError('invalid_ssh_key', 'The key is not an Ed25519, ECDSA P-256/P-384 or RSA key')
}

function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** A WebCrypto key for verifying signatures made with this key (not for sk keys). */
export async function importSshVerifyKey(key: SshPublicKey, rsaHash: 'SHA-256' | 'SHA-512' = 'SHA-512'): Promise<CryptoKey> {
  if (key.family === 'ed25519') return crypto.subtle.importKey('raw', key.point!, { name: 'Ed25519' }, false, ['verify'])
  if (key.family === 'ecdsa') {
    return crypto.subtle.importKey('raw', key.point!, { name: 'ECDSA', namedCurve: key.curve === 'nistp256' ? 'P-256' : 'P-384' }, false, ['verify'])
  }
  const toUrl = (v: Uint8Array) => toBase64(v).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return crypto.subtle.importKey('jwk', { kty: 'RSA', e: toUrl(key.rsa!.e), n: toUrl(key.rsa!.n), alg: rsaHash === 'SHA-512' ? 'RS512' : 'RS256' }, { name: 'RSASSA-PKCS1-v1_5', hash: rsaHash }, false, ['verify'])
}
