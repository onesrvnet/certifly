import { createHash, createHmac, createPublicKey, type KeyObject, timingSafeEqual, verify } from 'node:crypto'

/*
 * JSON Web Signatures as ACME uses them (RFC 8555 §6.2): the flattened JSON serialization,
 * signed with the account key (ES256, ES384, RS256, EdDSA) or, for external account binding,
 * with an HMAC. Verification only; certifly never signs a JWS.
 */

export type JwsErrorKind = 'malformed' | 'bad_algorithm' | 'bad_public_key' | 'bad_signature'

/** A refusal with a kind the ACME layer maps to its error types. */
export class JwsError extends Error {
  constructor(
    readonly kind: JwsErrorKind,
    message: string,
  ) {
    super(message)
    this.name = 'JwsError'
  }
}

export type JwsAlgorithm = 'ES256' | 'ES384' | 'RS256' | 'EdDSA'
export const JWS_ALGORITHMS: readonly JwsAlgorithm[] = ['ES256', 'ES384', 'RS256', 'EdDSA']
export type HmacAlgorithm = 'HS256' | 'HS384' | 'HS512'
const HMAC_HASHES: Record<HmacAlgorithm, string> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }

/** The public members of a JWK (RFC 7517), the only ones certifly keeps. */
export type PublicJwk =
  | { kty: 'EC'; crv: 'P-256' | 'P-384'; x: string; y: string }
  | { kty: 'RSA'; n: string; e: string }
  | { kty: 'OKP'; crv: 'Ed25519'; x: string }

const MIN_RSA_BITS = 2048
const MAX_RSA_BITS = 8192
const B64URL = /^[A-Za-z0-9_-]*$/

/** Strict base64url (no padding, no other characters). */
export function decodeBase64Url(value: unknown, what = 'value'): Buffer {
  if (typeof value !== 'string' || !B64URL.test(value) || value.length % 4 === 1) throw new JwsError('malformed', `${what} is not base64url`)
  return Buffer.from(value, 'base64url')
}

export const encodeBase64Url = (data: Uint8Array | string): string => Buffer.from(data).toString('base64url')

export interface ParsedJws {
  /** The decoded protected header. */
  header: Record<string, unknown>
  protected_b64: string
  payload_b64: string
  signature_b64: string
  /** The decoded payload; empty for a POST-as-GET (RFC 8555 §6.3). */
  payload: Buffer
  signature: Buffer
}

/** Parses a flattened JWS: exactly `protected`, `payload` and `signature`, the header a JSON object. */
export function parseJws(body: unknown): ParsedJws {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new JwsError('malformed', 'The request body must be a flattened JWS')
  const raw = body as Record<string, unknown>
  for (const key of Object.keys(raw)) {
    if (key !== 'protected' && key !== 'payload' && key !== 'signature') throw new JwsError('malformed', `Unexpected member "${key}" in the JWS`)
  }
  const protected_b64 = raw.protected
  const payload_b64 = raw.payload
  const signature_b64 = raw.signature
  if (typeof protected_b64 !== 'string' || typeof payload_b64 !== 'string' || typeof signature_b64 !== 'string') {
    throw new JwsError('malformed', 'The JWS needs protected, payload and signature')
  }
  let header: unknown
  try {
    header = JSON.parse(decodeBase64Url(protected_b64, 'The protected header').toString('utf8'))
  } catch (error) {
    if (error instanceof JwsError) throw error
    throw new JwsError('malformed', 'The protected header is not JSON')
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new JwsError('malformed', 'The protected header must be a JSON object')
  return {
    header: header as Record<string, unknown>,
    protected_b64,
    payload_b64,
    signature_b64,
    payload: decodeBase64Url(payload_b64, 'The payload'),
    signature: decodeBase64Url(signature_b64, 'The signature'),
  }
}

/** Parses the JSON payload of a JWS into an object. */
export function jwsPayloadObject(jws: Pick<ParsedJws, 'payload'>): Record<string, unknown> {
  let value: unknown
  try {
    value = JSON.parse(jws.payload.toString('utf8'))
  } catch {
    throw new JwsError('malformed', 'The payload is not JSON')
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new JwsError('malformed', 'The payload must be a JSON object')
  return value as Record<string, unknown>
}

function member(jwk: Record<string, unknown>, name: string): string {
  const value = jwk[name]
  if (typeof value !== 'string' || !value || !B64URL.test(value)) throw new JwsError('bad_public_key', `The JWK member "${name}" is missing or not base64url`)
  return value
}

/**
 * Validates a public JWK and keeps only its public members. Refuses private keys, key types
 * ACME clients should not use here, and RSA keys under 2048 bits. The key is also imported once,
 * which rejects points that are not on the curve.
 */
export function normalizeJwk(input: unknown): PublicJwk {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new JwsError('bad_public_key', 'The JWK must be an object')
  const jwk = input as Record<string, unknown>
  for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth']) {
    if (secret in jwk) throw new JwsError('bad_public_key', 'The JWK must not contain private key material')
  }
  let out: PublicJwk
  switch (jwk.kty) {
    case 'EC': {
      if (jwk.crv !== 'P-256' && jwk.crv !== 'P-384') throw new JwsError('bad_public_key', 'Only the P-256 and P-384 curves are supported')
      out = { kty: 'EC', crv: jwk.crv, x: member(jwk, 'x'), y: member(jwk, 'y') }
      break
    }
    case 'RSA': {
      out = { kty: 'RSA', n: member(jwk, 'n'), e: member(jwk, 'e') }
      const bits = decodeBase64Url(out.n).length * 8
      if (bits < MIN_RSA_BITS || bits > MAX_RSA_BITS) throw new JwsError('bad_public_key', `RSA keys must be ${MIN_RSA_BITS} to ${MAX_RSA_BITS} bits`)
      break
    }
    case 'OKP': {
      if (jwk.crv !== 'Ed25519') throw new JwsError('bad_public_key', 'Only Ed25519 is supported')
      out = { kty: 'OKP', crv: 'Ed25519', x: member(jwk, 'x') }
      break
    }
    default:
      throw new JwsError('bad_public_key', 'The JWK key type must be EC, RSA or OKP')
  }
  keyObject(out)
  return out
}

/** The key as Node's crypto reads it. */
export function keyObject(jwk: PublicJwk): KeyObject {
  try {
    return createPublicKey({ key: jwk, format: 'jwk' })
  } catch {
    throw new JwsError('bad_public_key', 'The JWK is not a valid public key')
  }
}

/** The signature algorithm that fits a key. */
export function algorithmFor(jwk: PublicJwk): JwsAlgorithm {
  if (jwk.kty === 'EC') return jwk.crv === 'P-256' ? 'ES256' : 'ES384'
  return jwk.kty === 'RSA' ? 'RS256' : 'EdDSA'
}

/** RFC 7638 thumbprint: SHA-256 over the JWK's required members in lexicographic order, base64url. */
export function jwkThumbprint(jwk: PublicJwk): string {
  const canonical =
    jwk.kty === 'EC'
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      : jwk.kty === 'RSA'
        ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
        : { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
  return createHash('sha256').update(JSON.stringify(canonical)).digest('base64url')
}

/** The SubjectPublicKeyInfo DER of a JWK, to compare with a certificate's key. */
export function jwkSpki(jwk: PublicJwk): Buffer {
  return keyObject(jwk).export({ type: 'spki', format: 'der' })
}

/**
 * Verifies the signature of a JWS with a public key. The header's `alg` must be the one that
 * fits the key: a key never verifies under another algorithm.
 */
export function verifyJws(jws: ParsedJws, jwk: PublicJwk): void {
  const alg = jws.header.alg
  if (typeof alg !== 'string' || !(JWS_ALGORITHMS as readonly string[]).includes(alg)) throw new JwsError('bad_algorithm', 'Unsupported signature algorithm')
  if (alg !== algorithmFor(jwk)) throw new JwsError('bad_algorithm', 'The signature algorithm does not fit the key')
  const key = keyObject(jwk)
  const data = Buffer.from(`${jws.protected_b64}.${jws.payload_b64}`, 'ascii')
  let ok = false
  try {
    switch (alg) {
      case 'ES256':
        ok = verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, jws.signature)
        break
      case 'ES384':
        ok = verify('sha384', data, { key, dsaEncoding: 'ieee-p1363' }, jws.signature)
        break
      case 'RS256':
        ok = verify('sha256', data, key, jws.signature)
        break
      case 'EdDSA':
        ok = verify(null, data, key, jws.signature)
        break
    }
  } catch {
    ok = false
  }
  if (!ok) throw new JwsError('bad_signature', 'The JWS signature does not verify')
}

/** Verifies an HMAC-signed JWS (the external account binding) with the shared key. */
export function verifyHmacJws(jws: ParsedJws, key: Uint8Array): void {
  const alg = jws.header.alg
  if (typeof alg !== 'string' || !(alg in HMAC_HASHES)) throw new JwsError('bad_algorithm', 'The binding must be signed with HS256, HS384 or HS512')
  const expected = createHmac(HMAC_HASHES[alg as HmacAlgorithm], key).update(`${jws.protected_b64}.${jws.payload_b64}`, 'ascii').digest()
  if (expected.length !== jws.signature.length || !timingSafeEqual(expected, jws.signature)) throw new JwsError('bad_signature', 'The binding signature does not verify')
}

/** RFC 8555 §8.1: the token joined with the account key's thumbprint. */
export function keyAuthorization(token: string, jwk: PublicJwk): string {
  return `${token}.${jwkThumbprint(jwk)}`
}
