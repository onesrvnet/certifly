import { createHmac, createSign, generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  algorithmFor,
  encodeBase64Url,
  jwkSpki,
  jwkThumbprint,
  jwsPayloadObject,
  JwsError,
  keyAuthorization,
  normalizeJwk,
  parseJws,
  verifyHmacJws,
  verifyJws,
  type PublicJwk,
} from '../src/index'

type Kind = 'ES256' | 'ES384' | 'RS256' | 'EdDSA'

function keyFor(kind: Kind): { privateKey: KeyObject; jwk: PublicJwk } {
  const pair =
    kind === 'ES256'
      ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
      : kind === 'ES384'
        ? generateKeyPairSync('ec', { namedCurve: 'P-384' })
        : kind === 'RS256'
          ? generateKeyPairSync('rsa', { modulusLength: 2048 })
          : generateKeyPairSync('ed25519')
  return { privateKey: pair.privateKey, jwk: normalizeJwk(pair.publicKey.export({ format: 'jwk' })) }
}

/** A flattened JWS signed like an ACME client would. */
function signJws(kind: Kind, privateKey: KeyObject, header: Record<string, unknown>, payload: unknown) {
  const protected_b64 = encodeBase64Url(JSON.stringify({ alg: kind, ...header }))
  const payload_b64 = payload === '' ? '' : encodeBase64Url(JSON.stringify(payload))
  const data = Buffer.from(`${protected_b64}.${payload_b64}`)
  const signature =
    kind === 'ES256'
      ? sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })
      : kind === 'ES384'
        ? sign('sha384', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })
        : kind === 'RS256'
          ? createSign('sha256').update(data).sign(privateKey)
          : sign(null, data, privateKey)
  return { protected: protected_b64, payload: payload_b64, signature: encodeBase64Url(signature) }
}

describe('JWK thumbprints (RFC 7638)', () => {
  it('matches the RFC 7638 example key', () => {
    const jwk = normalizeJwk({
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
      kid: '2011-04-29',
    })
    expect(jwkThumbprint(jwk)).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
  })

  it('ignores extra members and key order', () => {
    const { jwk } = keyFor('ES256')
    const shuffled = { ...(jwk as object), kid: 'x', use: 'sig' } as Record<string, unknown>
    expect(jwkThumbprint(normalizeJwk(shuffled))).toBe(jwkThumbprint(jwk))
  })

  it('differs between keys and builds the key authorization from it', () => {
    const a = keyFor('ES256').jwk
    const b = keyFor('ES256').jwk
    expect(jwkThumbprint(a)).not.toBe(jwkThumbprint(b))
    expect(keyAuthorization('tok', a)).toBe(`tok.${jwkThumbprint(a)}`)
  })
})

describe('JWK validation', () => {
  it('refuses private keys, other curves, small RSA keys and unknown types', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' })
    expect(() => normalizeJwk(ec)).toThrow(/private/)
    const p521 = generateKeyPairSync('ec', { namedCurve: 'P-521' }).publicKey.export({ format: 'jwk' })
    expect(() => normalizeJwk(p521)).toThrow(/P-256 and P-384/)
    const rsa1024 = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' })
    expect(() => normalizeJwk(rsa1024)).toThrow(/2048/)
    expect(() => normalizeJwk({ kty: 'oct', k: 'AAAA' })).toThrow(JwsError)
    expect(() => normalizeJwk(null)).toThrow(JwsError)
  })

  it('refuses a point that is not on the curve', () => {
    const { jwk } = keyFor('ES256')
    if (jwk.kty !== 'EC') throw new Error('unreachable')
    expect(() => normalizeJwk({ ...jwk, y: jwk.x })).toThrow(/not a valid public key/)
  })

  it('keeps only public members and picks the algorithm from the key', () => {
    expect(algorithmFor(keyFor('ES256').jwk)).toBe('ES256')
    expect(algorithmFor(keyFor('ES384').jwk)).toBe('ES384')
    expect(algorithmFor(keyFor('RS256').jwk)).toBe('RS256')
    expect(algorithmFor(keyFor('EdDSA').jwk)).toBe('EdDSA')
    expect(Object.keys(normalizeJwk({ ...keyFor('ES256').jwk, use: 'sig', kid: 'a' })).sort()).toEqual(['crv', 'kty', 'x', 'y'])
  })

  it('exports the SPKI that matches the key', () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const jwk = normalizeJwk(pair.publicKey.export({ format: 'jwk' }))
    expect(jwkSpki(jwk).equals(pair.publicKey.export({ type: 'spki', format: 'der' }))).toBe(true)
  })
})

describe('JWS verification', () => {
  for (const kind of ['ES256', 'ES384', 'RS256', 'EdDSA'] as const) {
    it(`verifies ${kind} and rejects a changed payload or signature`, () => {
      const { privateKey, jwk } = keyFor(kind)
      const body = signJws(kind, privateKey, { nonce: 'n', url: 'https://x/y', jwk }, { hello: 'world' })
      const jws = parseJws(body)
      expect(() => verifyJws(jws, jwk)).not.toThrow()
      expect(jwsPayloadObject(jws)).toEqual({ hello: 'world' })

      const tampered = parseJws({ ...body, payload: encodeBase64Url(JSON.stringify({ hello: 'evil' })) })
      expect(() => verifyJws(tampered, jwk)).toThrow(/does not verify/)
      const other = keyFor(kind).jwk
      expect(() => verifyJws(jws, other)).toThrow(/does not verify/)
    })
  }

  it('refuses an algorithm that does not fit the key, and unsupported ones', () => {
    const { privateKey, jwk } = keyFor('ES256')
    const wrong = parseJws(signJws('ES256', privateKey, {}, {}))
    expect(() => verifyJws(wrong, keyFor('RS256').jwk)).toThrow(/does not fit/)
    const none = parseJws({ protected: encodeBase64Url(JSON.stringify({ alg: 'none' })), payload: '', signature: '' })
    expect(() => verifyJws(none, jwk)).toThrow(/Unsupported/)
    const hs = parseJws({ protected: encodeBase64Url(JSON.stringify({ alg: 'HS256' })), payload: '', signature: encodeBase64Url('x') })
    expect(() => verifyJws(hs, jwk)).toThrow(JwsError)
  })

  it('treats an empty payload as POST-as-GET', () => {
    const { privateKey, jwk } = keyFor('ES256')
    const jws = parseJws(signJws('ES256', privateKey, {}, ''))
    expect(jws.payload.length).toBe(0)
    expect(() => verifyJws(jws, jwk)).not.toThrow()
  })

  it('refuses malformed envelopes', () => {
    expect(() => parseJws('nope')).toThrow(JwsError)
    expect(() => parseJws({ protected: 'e30', payload: '', signature: '', header: {} })).toThrow(/Unexpected member/)
    expect(() => parseJws({ protected: 'e30', payload: '' })).toThrow(/needs/)
    expect(() => parseJws({ protected: '!!!', payload: '', signature: '' })).toThrow(/base64url/)
    expect(() => parseJws({ protected: encodeBase64Url('[1]'), payload: '', signature: '' })).toThrow(/JSON object/)
    expect(() => parseJws({ protected: encodeBase64Url('not json'), payload: '', signature: '' })).toThrow(/JSON/)
  })
})

describe('HMAC JWS (external account binding)', () => {
  const key = Buffer.from('k'.repeat(32))
  const make = (alg: string, mac = key) => {
    const protected_b64 = encodeBase64Url(JSON.stringify({ alg, kid: 'kid', url: 'https://x/new-account' }))
    const payload_b64 = encodeBase64Url(JSON.stringify({ kty: 'EC' }))
    const hash = alg === 'HS256' ? 'sha256' : alg === 'HS384' ? 'sha384' : 'sha512'
    return parseJws({ protected: protected_b64, payload: payload_b64, signature: encodeBase64Url(createHmac(hash, mac).update(`${protected_b64}.${payload_b64}`).digest()) })
  }

  it('verifies HS256, HS384 and HS512 with the right key only', () => {
    for (const alg of ['HS256', 'HS384', 'HS512']) {
      expect(() => verifyHmacJws(make(alg), key)).not.toThrow()
      expect(() => verifyHmacJws(make(alg), Buffer.from('x'.repeat(32)))).toThrow(/does not verify/)
    }
  })

  it('refuses other algorithms', () => {
    expect(() => verifyHmacJws(parseJws({ protected: encodeBase64Url(JSON.stringify({ alg: 'ES256' })), payload: '', signature: '' }), key)).toThrow(/HS256/)
  })
})
