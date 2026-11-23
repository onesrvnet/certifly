import { bytes, toHex } from '../encoding'
import { PkiError } from '../errors'
import * as x509 from '../x509'
import type { SshPublicKey } from './keys'
import { SshReader } from './wire'
import { YUBICO_FIDO_INTERMEDIATES, YUBICO_FIDO_ROOTS } from './yubico-roots'

const MAGIC = 'ssh-sk-attest-v01'
/** id-fido-gen-ce-aaguid: the authenticator model, in the attestation certificate. */
const AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4'
const FLAG_USER_PRESENT = 0x01
const FLAG_ATTESTED_CREDENTIAL = 0x40

function bad(message: string): never {
  throw new PkiError('invalid_ssh_attestation', message)
}

// --- a minimal CBOR reader (RFC 8949), enough for COSE keys ---------------------------------

type Cbor = number | bigint | Uint8Array | string | Cbor[] | Map<Cbor, Cbor>

function readCbor(data: Uint8Array, offset: number, depth = 0): { value: Cbor; end: number } {
  if (depth > 8 || offset >= data.byteLength) bad('The attestation data is malformed')
  const initial = data[offset]!
  const major = initial >> 5
  const info = initial & 0x1f
  let pos = offset + 1
  let length: number
  if (info < 24) length = info
  else if (info === 24 || info === 25 || info === 26) {
    const size = info === 24 ? 1 : info === 25 ? 2 : 4
    if (pos + size > data.byteLength) bad('The attestation data is malformed')
    length = 0
    for (let i = 0; i < size; i++) length = length * 256 + data[pos + i]!
    pos += size
  } else bad('The attestation data uses an unsupported encoding')
  switch (major) {
    case 0:
      return { value: length, end: pos }
    case 1:
      return { value: -1 - length, end: pos }
    case 2:
    case 3: {
      if (pos + length > data.byteLength) bad('The attestation data is malformed')
      const slice = bytes(data.subarray(pos, pos + length))
      return { value: major === 2 ? slice : new TextDecoder().decode(slice), end: pos + length }
    }
    case 4: {
      const items: Cbor[] = []
      for (let i = 0; i < length; i++) {
        const item = readCbor(data, pos, depth + 1)
        items.push(item.value)
        pos = item.end
      }
      return { value: items, end: pos }
    }
    case 5: {
      const map = new Map<Cbor, Cbor>()
      for (let i = 0; i < length; i++) {
        const key = readCbor(data, pos, depth + 1)
        const value = readCbor(data, key.end, depth + 1)
        map.set(key.value, value.value)
        pos = value.end
      }
      return { value: map, end: pos }
    }
    default:
      bad('The attestation data uses an unsupported encoding')
  }
}

// --- authenticator data (WebAuthn §6.1) -------------------------------------------------------

interface AuthData {
  rp_id_hash: Uint8Array
  flags: number
  aaguid: Uint8Array
  credential_id: Uint8Array
  /** The credential public key as an SSH key point: the Ed25519 key, or the uncompressed EC point. */
  point: Uint8Array
  family: 'ed25519' | 'ecdsa'
}

function parseAuthData(data: Uint8Array): AuthData {
  if (data.byteLength < 37) bad('The authenticator data is too short')
  const flags = data[32]!
  if (!(flags & FLAG_ATTESTED_CREDENTIAL)) bad('The authenticator data has no credential')
  const reader = new SshReader(data.subarray(37))
  const aaguid = reader.rawBytes(16)
  const idLength = (reader.byte() << 8) | reader.byte()
  const credential_id = reader.rawBytes(idLength)
  const rest = data.subarray(37 + 16 + 2 + idLength)
  const cose = readCbor(rest, 0).value
  if (!(cose instanceof Map)) bad('The credential public key is malformed')
  const kty = cose.get(1)
  const crv = cose.get(-1)
  const x = cose.get(-2)
  if (kty === 1 && crv === 6 && x instanceof Uint8Array && x.byteLength === 32) {
    return { rp_id_hash: bytes(data.subarray(0, 32)), flags, aaguid, credential_id, point: x, family: 'ed25519' }
  }
  const y = cose.get(-3)
  if (kty === 2 && crv === 1 && x instanceof Uint8Array && y instanceof Uint8Array && x.byteLength === 32 && y.byteLength === 32) {
    const point = new Uint8Array(65)
    point[0] = 4
    point.set(x, 1)
    point.set(y, 33)
    return { rp_id_hash: bytes(data.subarray(0, 32)), flags, aaguid, credential_id, point, family: 'ecdsa' }
  }
  bad('The credential key type is not supported')
}

// --- certificate chain -----------------------------------------------------------------------

function trustedStore(extra: readonly string[]): { roots: x509.X509Certificate[]; intermediates: x509.X509Certificate[] } {
  return {
    roots: [...YUBICO_FIDO_ROOTS, ...extra].map((pem) => new x509.X509Certificate(pem)),
    intermediates: YUBICO_FIDO_INTERMEDIATES.map((pem) => new x509.X509Certificate(pem)),
  }
}

async function chainsToRoot(leaf: x509.X509Certificate, store: ReturnType<typeof trustedStore>, now: Date): Promise<boolean> {
  const inWindow = (c: x509.X509Certificate) => c.notBefore <= now && now <= c.notAfter
  if (!inWindow(leaf)) return false
  let current = leaf
  for (let depth = 0; depth < 4; depth++) {
    for (const root of store.roots) {
      if (root.subject === current.issuer && inWindow(root) && (await current.verify({ publicKey: root.publicKey, signatureOnly: true }).catch(() => false))) return true
    }
    let next: x509.X509Certificate | undefined
    for (const candidate of store.intermediates) {
      if (candidate.subject === current.issuer && inWindow(candidate) && (await current.verify({ publicKey: candidate.publicKey, signatureOnly: true }).catch(() => false))) {
        next = candidate
        break
      }
    }
    if (!next) return false
    current = next
  }
  return false
}

/** An ECDSA signature in DER (RFC 3279 Ecdsa-Sig-Value) as r || s of fixed width. */
function ecdsaDerToRaw(der: Uint8Array, width: number): Uint8Array<ArrayBuffer> {
  const fail = (): never => bad('The attestation signature is malformed')
  if (der[0] !== 0x30) fail()
  let pos = 2
  if (der[1]! & 0x80) pos = 2 + (der[1]! & 0x7f)
  const out = new Uint8Array(width * 2)
  for (const slot of [0, 1]) {
    if (der[pos] !== 0x02) fail()
    let length = der[pos + 1]!
    if (length & 0x80) fail()
    let start = pos + 2
    if (start + length > der.byteLength) fail()
    while (length > 0 && der[start] === 0) {
      start++
      length--
    }
    if (length > width) fail()
    out.set(der.subarray(start, start + length), slot * width + (width - length))
    pos = start + length
  }
  return out
}

export interface FidoAttestation {
  /** Authenticator model identifier, lowercase hex, 32 digits. */
  aaguid: string
  /** The subject of the attestation certificate, for the audit trail. */
  certificate_subject: string
  user_present: boolean
}

export interface VerifyFidoAttestationParams {
  /** The file `ssh-keygen -O write-attestation=` wrote. */
  attestation: Uint8Array
  /** The security key being attested. */
  key: SshPublicKey
  /** The challenge given to `ssh-keygen -O challenge=`. */
  challenge: Uint8Array
  now?: Date
  /** More trusted roots, as PEM. For tests; production uses only the bundled Yubico roots. */
  extra_roots?: readonly string[]
  /** More intermediates, as PEM. For tests. */
  extra_intermediates?: readonly string[]
}

/**
 * Checks that a FIDO security key was made by a genuine Yubico authenticator:
 * 1. the attestation certificate chains to a bundled Yubico root;
 * 2. the credential in the authenticator data is exactly the submitted key, for the key's application;
 * 3. the attestation signature over authenticator data and the hash of the challenge verifies
 *    with the certificate's key;
 * 4. the certificate's AAGUID, when present, matches the authenticator data.
 *
 * `ssh-keygen` hands the challenge to the authenticator, which signs SHA-256 of it. A challenge
 * of exactly 32 bytes is also accepted as the hash itself, which some libfido2 versions use.
 */
export async function verifyFidoAttestation(params: VerifyFidoAttestationParams): Promise<FidoAttestation> {
  const { key } = params
  if (!key.sk || !key.application) bad('Only security keys can be attested')
  const reader = new SshReader(params.attestation)
  let certDer: Uint8Array, signature: Uint8Array, authdata: Uint8Array
  try {
    if (reader.text() !== MAGIC) bad('Not an SSH attestation file')
    certDer = reader.string()
    signature = reader.string()
    authdata = reader.string()
    reader.uint32()
    reader.string()
    reader.expectEnd()
  } catch (error) {
    if (error instanceof PkiError && error.code === 'invalid_ssh_attestation') throw error
    bad('The attestation file is malformed')
  }

  const auth = parseAuthData(authdata)
  const applicationHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(new TextEncoder().encode(key.application))))
  if (toHex(auth.rp_id_hash) !== toHex(applicationHash)) bad('The attestation belongs to another application')
  if (auth.family !== key.family || toHex(auth.point) !== toHex(key.point!)) bad('The attestation is for a different key')

  let leaf: x509.X509Certificate
  try {
    leaf = new x509.X509Certificate(bytes(certDer))
  } catch {
    bad('The attestation certificate is not valid')
  }
  const store = trustedStore(params.extra_roots ?? [])
  for (const pem of params.extra_intermediates ?? []) store.intermediates.push(new x509.X509Certificate(pem))
  if (!(await chainsToRoot(leaf, store, params.now ?? new Date()))) bad('The attestation certificate does not chain to a Yubico root')

  const aaguidExt = leaf.getExtension(AAGUID_OID)
  if (aaguidExt) {
    const value = new Uint8Array(aaguidExt.value)
    const certAaguid = value.byteLength === 18 && value[0] === 0x04 && value[1] === 0x10 ? value.subarray(2) : value
    if (toHex(certAaguid) !== toHex(auth.aaguid)) bad('The attestation certificate is for a different authenticator model')
  }

  // The attestation signature covers authdata || clientDataHash (packed), or, for U2F-only
  // authenticators, 0x00 || rpIdHash || clientDataHash || credentialId || public key.
  const challenge = bytes(params.challenge)
  if (challenge.byteLength === 0) bad('The challenge is empty')
  const hashes = [new Uint8Array(await crypto.subtle.digest('SHA-256', challenge))]
  if (challenge.byteLength === 32) hashes.push(challenge)
  const u2fKey = auth.family === 'ecdsa' ? auth.point : null
  const candidates: Uint8Array[] = []
  for (const hash of hashes) {
    candidates.push(concat(authdata, hash))
    if (u2fKey) candidates.push(concat(new Uint8Array([0]), auth.rp_id_hash, hash, auth.credential_id, u2fKey))
  }
  const curve = (leaf.publicKey.algorithm as { namedCurve?: string }).namedCurve
  if (curve !== 'P-256' && curve !== 'P-384') bad('The attestation certificate key is not supported')
  const certKey = await leaf.publicKey.export({ name: 'ECDSA', namedCurve: curve }, ['verify'])
  const raw = ecdsaDerToRaw(signature, curve === 'P-256' ? 32 : 48)
  const hashName = curve === 'P-256' ? 'SHA-256' : 'SHA-384'
  let ok = false
  for (const message of candidates) {
    if (await crypto.subtle.verify({ name: 'ECDSA', hash: hashName }, certKey, raw, bytes(message))) {
      ok = true
      break
    }
  }
  if (!ok) bad('The attestation signature does not verify')
  return { aaguid: toHex(auth.aaguid), certificate_subject: leaf.subject, user_present: Boolean(auth.flags & FLAG_USER_PRESENT) }
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.byteLength
  }
  return out
}
