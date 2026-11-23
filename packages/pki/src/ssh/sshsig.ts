import { bytes } from '../encoding'
import { PkiError } from '../errors'
import { importSshVerifyKey, parseSshPublicKeyBlob, type ParseKeyOptions, type SshPublicKey } from './keys'
import { SshReader, SshWriter } from './wire'

const MAGIC = new Uint8Array([0x53, 0x53, 0x48, 0x53, 0x49, 0x47]) // "SSHSIG"
const BEGIN = '-----BEGIN SSH SIGNATURE-----'
const END = '-----END SSH SIGNATURE-----'

function bad(message: string): never {
  throw new PkiError('invalid_ssh_signature', message)
}

function dearmor(text: string): Uint8Array<ArrayBuffer> {
  const lines = text.trim().split(/\r?\n/)
  if (lines[0]?.trim() !== BEGIN || lines[lines.length - 1]?.trim() !== END) bad('Not an armored SSH signature')
  const body = lines.slice(1, -1).join('').replace(/\s+/g, '')
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body) || body.length % 4 !== 0) bad('The signature is not valid base64')
  const binary = atob(body)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** Pads or trims an mpint magnitude to a fixed width. */
function fixedWidth(value: Uint8Array, width: number): Uint8Array {
  if (value.byteLength > width) bad('The ECDSA signature is malformed')
  const out = new Uint8Array(width)
  out.set(value, width - value.byteLength)
  return out
}

export interface SshsigResult {
  public_key: SshPublicKey
  hash_algorithm: 'sha256' | 'sha512'
}

/**
 * Verifies an armored SSHSIG (PROTOCOL.sshsig) over `message` and returns the signing key. The
 * namespace must be exactly `namespace`. The caller still has to decide whether it trusts the
 * returned key. FIDO security-key signatures are not accepted here.
 */
export async function verifySshsig(armored: string, message: Uint8Array, namespace: string, options: ParseKeyOptions = {}): Promise<SshsigResult> {
  const reader = new SshReader(dearmor(armored))
  if (!bytes(reader.rawBytes(6)).every((b, i) => b === MAGIC[i])) bad('Not an SSH signature')
  if (reader.uint32() !== 1) bad('Unsupported signature version')
  const key = await parseSshPublicKeyBlob(reader.string(), '', options).catch((error) => {
    throw error instanceof PkiError ? new PkiError('invalid_ssh_signature', error.message) : error
  })
  if (key.sk) bad('Security key signatures are not accepted')
  const signedNamespace = reader.text()
  if (signedNamespace !== namespace) bad('The signature was made for a different namespace')
  reader.string() // reserved
  const hashName = reader.text()
  if (hashName !== 'sha256' && hashName !== 'sha512') bad('Unsupported hash algorithm')
  const signature = new SshReader(reader.string())
  reader.expectEnd()

  const digest = new Uint8Array(await crypto.subtle.digest(hashName === 'sha256' ? 'SHA-256' : 'SHA-512', bytes(message)))
  const signed = new SshWriter().raw(MAGIC).string(signedNamespace).string(new Uint8Array(0)).string(hashName).string(digest).toBytes()

  const sigType = signature.text()
  const sigBlob = signature.string()
  signature.expectEnd()
  let ok = false
  if (key.family === 'ed25519') {
    if (sigType !== 'ssh-ed25519') bad('The signature type does not match the key')
    ok = await crypto.subtle.verify({ name: 'Ed25519' }, await importSshVerifyKey(key), sigBlob, signed)
  } else if (key.family === 'ecdsa') {
    if (sigType !== `ecdsa-sha2-${key.curve}`) bad('The signature type does not match the key')
    const inner = new SshReader(sigBlob)
    const width = key.curve === 'nistp256' ? 32 : 48
    const raw = new Uint8Array(width * 2)
    raw.set(fixedWidth(inner.mpint(), width), 0)
    raw.set(fixedWidth(inner.mpint(), width), width)
    inner.expectEnd()
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: key.curve === 'nistp256' ? 'SHA-256' : 'SHA-384' }, await importSshVerifyKey(key), raw, signed)
  } else {
    if (sigType !== 'rsa-sha2-256' && sigType !== 'rsa-sha2-512') bad('RSA signatures must use SHA-2')
    const hash = sigType === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256'
    ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, await importSshVerifyKey(key, hash), sigBlob, signed)
  }
  if (!ok) bad('The signature does not verify')
  return { public_key: key, hash_algorithm: hashName }
}
