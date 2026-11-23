import { bytes, pemDecodeAll } from '../encoding'
import { PkiError } from '../errors'
import { SshReader } from './wire'

const AUTH_MAGIC = new TextEncoder().encode('openssh-key-v1\0')

export interface ImportedPrivateKey {
  /** PKCS#8 DER, for the keyvault to encrypt. The caller wipes it when done. */
  pkcs8: Uint8Array<ArrayBuffer>
}

function bad(message: string): never {
  throw new PkiError('invalid_ssh_key', message)
}

// --- a few DER builders: just enough to wrap OpenSSH key fields into PKCS#8 -----------------

function der(tag: number, ...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const length = parts.reduce((n, p) => n + p.byteLength, 0)
  let header: number[]
  if (length < 0x80) header = [tag, length]
  else if (length < 0x100) header = [tag, 0x81, length]
  else if (length < 0x10000) header = [tag, 0x82, length >> 8, length & 0xff]
  else header = [tag, 0x83, length >> 16, (length >> 8) & 0xff, length & 0xff]
  const out = new Uint8Array(header.length + length)
  out.set(header)
  let offset = header.length
  for (const part of parts) {
    out.set(part, offset)
    offset += part.byteLength
  }
  return out
}

function derInteger(magnitude: Uint8Array): Uint8Array<ArrayBuffer> {
  let start = 0
  while (start < magnitude.byteLength - 1 && magnitude[start] === 0) start++
  const trimmed = magnitude.subarray(start)
  if (trimmed.byteLength === 0) return der(0x02, new Uint8Array([0]))
  return der(0x02, trimmed[0]! & 0x80 ? Uint8Array.of(0, ...trimmed) : trimmed)
}

function toBigInt(value: Uint8Array): bigint {
  let out = 0n
  for (const b of value) out = (out << 8n) | BigInt(b)
  return out
}

function fromBigInt(value: bigint): Uint8Array<ArrayBuffer> {
  let hex = value.toString(16)
  if (hex.length % 2) hex = `0${hex}`
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

const OID_RSA = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01)
const OID_EC = Uint8Array.of(0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01)
const OID_P256 = Uint8Array.of(0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07)
const OID_P384 = Uint8Array.of(0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22)
const OID_ED25519 = Uint8Array.of(0x06, 0x03, 0x2b, 0x65, 0x70)
const NULL = Uint8Array.of(0x05, 0x00)

function pkcs8(algorithmId: Uint8Array, privateKey: Uint8Array): Uint8Array<ArrayBuffer> {
  return der(0x30, derInteger(new Uint8Array([0])), algorithmId, der(0x04, privateKey))
}

/** Plain, unencrypted private keys only. PKCS#8 PEM and `openssh-key-v1` are accepted. */
export function parsePrivateKeyForImport(text: string): ImportedPrivateKey {
  const blocks = pemDecodeAll(text)
  if (blocks.length !== 1) bad('Expected exactly one private key')
  const block = blocks[0]!
  if (block.label === 'PRIVATE KEY') return { pkcs8: block.der }
  if (block.label === 'ENCRYPTED PRIVATE KEY') {
    throw new PkiError('ssh_key_encrypted', 'The private key is encrypted. Remove the passphrase first, for example with: ssh-keygen -p -N "" -f <key>')
  }
  if (block.label !== 'OPENSSH PRIVATE KEY') bad('Expected a PKCS#8 or OpenSSH private key')
  return parseOpenSshPrivateKey(block.der)
}

export function parseOpenSshPrivateKey(data: Uint8Array): ImportedPrivateKey {
  const reader = new SshReader(data)
  const magic = reader.rawBytes(AUTH_MAGIC.byteLength)
  if (!AUTH_MAGIC.every((b, i) => magic[i] === b)) bad('Not an OpenSSH private key')
  const cipher = reader.text()
  const kdf = reader.text()
  reader.string()
  if (cipher !== 'none' || kdf !== 'none') {
    throw new PkiError('ssh_key_encrypted', 'The private key is encrypted. Remove the passphrase first, for example with: ssh-keygen -p -N "" -f <key>')
  }
  if (reader.uint32() !== 1) bad('Files with several keys are not supported')
  reader.string() // the public key; the private section repeats it and is what we read
  const priv = new SshReader(reader.string())
  reader.expectEnd()
  if (priv.uint32() !== priv.uint32()) bad('The private key is corrupt')
  const type = priv.text()

  if (type === 'ssh-ed25519') {
    const pk = priv.string()
    const sk = priv.string()
    if (pk.byteLength !== 32 || sk.byteLength !== 64) bad('The Ed25519 key is malformed')
    if (!pk.every((b, i) => sk[32 + i] === b)) bad('The Ed25519 key halves do not match')
    // CurvePrivateKey ::= OCTET STRING (RFC 8410 §7): the seed, wrapped once more.
    return finish(pkcs8(der(0x30, OID_ED25519), der(0x04, sk.subarray(0, 32))))
  }
  if (type === 'ecdsa-sha2-nistp256' || type === 'ecdsa-sha2-nistp384') {
    const curve = priv.text()
    const point = priv.string()
    const d = priv.mpint()
    const size = type === 'ecdsa-sha2-nistp256' ? 32 : 48
    if (curve !== type.slice('ecdsa-sha2-'.length) || d.byteLength > size) bad('The ECDSA key is malformed')
    const scalar = new Uint8Array(size)
    scalar.set(d, size - d.byteLength)
    const ecPrivateKey = der(0x30, derInteger(Uint8Array.of(1)), der(0x04, scalar), der(0xa1, der(0x03, Uint8Array.of(0), point)))
    return finish(pkcs8(der(0x30, OID_EC, type === 'ecdsa-sha2-nistp256' ? OID_P256 : OID_P384), ecPrivateKey))
  }
  if (type === 'ssh-rsa') {
    const n = priv.mpint()
    const e = priv.mpint()
    const d = priv.mpint()
    const iqmp = priv.mpint()
    const p = priv.mpint()
    const q = priv.mpint()
    const bp = toBigInt(p)
    const bq = toBigInt(q)
    const bd = toBigInt(d)
    const rsaPrivateKey = der(
      0x30,
      derInteger(Uint8Array.of(0)),
      derInteger(n),
      derInteger(e),
      derInteger(d),
      derInteger(p),
      derInteger(q),
      derInteger(fromBigInt(bd % (bp - 1n))),
      derInteger(fromBigInt(bd % (bq - 1n))),
      derInteger(iqmp),
    )
    return finish(pkcs8(der(0x30, OID_RSA, NULL), rsaPrivateKey))
  }
  bad(`Unsupported private key type: ${type.slice(0, 64)}`)
}

function finish(key: Uint8Array<ArrayBuffer>): ImportedPrivateKey {
  return { pkcs8: bytes(key) }
}
