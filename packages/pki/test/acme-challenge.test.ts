import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { ACME_IDENTIFIER_OID, canonicalIp, inspectAcmeChallengeCertificate, keyAuthorizationDigest, reverseDnsName } from '../src/index'
import * as x509 from '../src/x509'

async function challengeCertificate(options: { names: { type: 'dns' | 'ip'; value: string }[]; digest?: string | null; critical?: boolean }) {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const extensions: x509.Extension[] = [new x509.SubjectAlternativeNameExtension(options.names)]
  if (options.digest !== null) {
    const digest = Buffer.from(options.digest ?? keyAuthorizationDigest('token.thumb'), 'hex')
    // DER OCTET STRING around the digest, as RFC 8737 §3 asks.
    extensions.push(new x509.Extension(ACME_IDENTIFIER_OID, options.critical ?? true, Buffer.concat([Buffer.from([0x04, digest.length]), digest])))
  }
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=challenge',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3_600_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions,
  })
  return new Uint8Array(cert.rawData)
}

describe('tls-alpn-01 certificates (RFC 8737)', () => {
  it('reads the SAN and the critical acmeIdentifier digest', async () => {
    const result = inspectAcmeChallengeCertificate(await challengeCertificate({ names: [{ type: 'dns', value: 'Example.test' }] }))
    expect(result.sans).toEqual([{ type: 'dns', value: 'example.test' }])
    expect(result.unsupported_sans).toEqual([])
    expect(result.acme_identifier).toEqual({ critical: true, digest_hex: createHash('sha256').update('token.thumb').digest('hex') })
  })

  it('reads an IP SAN, a non-critical extension, a malformed one and a missing one', async () => {
    expect(inspectAcmeChallengeCertificate(await challengeCertificate({ names: [{ type: 'ip', value: '192.0.2.1' }] })).sans).toEqual([{ type: 'ip', value: '192.0.2.1' }])
    expect(inspectAcmeChallengeCertificate(await challengeCertificate({ names: [{ type: 'dns', value: 'a.test' }], critical: false })).acme_identifier?.critical).toBe(false)
    expect(inspectAcmeChallengeCertificate(await challengeCertificate({ names: [{ type: 'dns', value: 'a.test' }], digest: 'abcd' })).acme_identifier?.digest_hex).toBeNull()
    expect(inspectAcmeChallengeCertificate(await challengeCertificate({ names: [{ type: 'dns', value: 'a.test' }], digest: null })).acme_identifier).toBeNull()
  })

  it('reports every SAN, so extra names can be refused', async () => {
    const result = inspectAcmeChallengeCertificate(await challengeCertificate({ names: [{ type: 'dns', value: 'a.test' }, { type: 'dns', value: 'b.test' }] }))
    expect(result.sans.map((san) => san.value)).toEqual(['a.test', 'b.test'])
  })

  it('refuses something that is not a certificate', () => {
    expect(() => inspectAcmeChallengeCertificate(new Uint8Array([1, 2, 3]))).toThrow(/valid certificate/)
  })

  it('hashes the key authorization as hex SHA-256', () => {
    expect(keyAuthorizationDigest('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})

describe('IP identifiers (RFC 8738)', () => {
  it('builds the reverse DNS name used as SNI', () => {
    expect(reverseDnsName('192.0.2.1')).toBe('1.2.0.192.in-addr.arpa')
    expect(reverseDnsName('2001:db8::567:89ab')).toBe('b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
    expect(() => reverseDnsName('not an ip')).toThrow()
  })

  it('writes an address in one canonical form', () => {
    expect(canonicalIp('2001:0db8:0:0:0:0:0:1')).toBe('2001:db8::1')
    expect(canonicalIp('192.0.2.1')).toBe('192.0.2.1')
    expect(canonicalIp('nope')).toBeNull()
  })
})
