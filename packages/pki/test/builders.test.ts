import { describe, expect, it } from 'vitest'
import {
  buildCaCsr,
  buildCrl,
  buildLeafCertificate,
  buildPkcs7CertsOnly,
  buildRootCertificate,
  certificateToPem,
  describePublicKey,
  fingerprint,
  generateLeafKeyPair,
  inspectCertificate,
  leafPrivateKeyToPem,
  parseCertificateBundle,
  parseCsr,
  pemDecodeAll,
  publicKeySpki,
  signIntermediate,
  x509Signing,
} from '../src/index'
import * as x509 from '../src/x509'
import { caKey, daysFromNow } from './helpers'

// The same builders as the OpenSSL suite, parsed back with x509 only, so they run without OpenSSL.

describe('certificate builders (no OpenSSL)', { timeout: 60_000 }, () => {
  it('builds a chain that x509 verifies link by link', async () => {
    const rootKey = await caKey('ecdsa-p256')
    const subKey = await caKey('rsa-2048')
    const root = await buildRootCertificate({ signer: rootKey.signer, public_key_spki: rootKey.public_key_spki, subject: 'CN=Pure Root', not_after: daysFromNow(365), path_length: null })
    const sub = await signIntermediate({
      issuer_certificate: root.pem,
      signer: rootKey.signer,
      public_key_spki: subKey.public_key_spki,
      subject: 'CN=Pure Sub',
      not_after: daysFromNow(180),
      path_length: 0,
      name_constraints: { permitted: { dns: ['pure.test'] } },
      crl_urls: ['http://pki.pure.test/root.crl'],
      ca_issuer_urls: ['http://pki.pure.test/root.crt'],
    })
    const pair = await generateLeafKeyPair('ecdsa-p256')
    const leaf = await buildLeafCertificate({
      issuer_certificate: sub.der,
      signer: subKey.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      subject: 'CN=www.pure.test',
      sans: [{ type: 'dns', value: 'www.pure.test' }],
      key_usages: ['digital_signature'],
      extended_key_usages: ['server_auth'],
      not_after: daysFromNow(30),
      crl_urls: [],
      ca_issuer_urls: [],
    })
    const chain = await new x509.X509ChainBuilder({ certificates: [new x509.X509Certificate(root.der), new x509.X509Certificate(sub.der)] }).build(new x509.X509Certificate(leaf.der))
    expect(chain.map((c) => c.subject)).toEqual(['CN=www.pure.test', 'CN=Pure Sub', 'CN=Pure Root'])

    const info = await inspectCertificate(sub.der)
    expect(info).toMatchObject({ is_ca: true, path_length: 0, basic_constraints_critical: true, crl_urls: ['http://pki.pure.test/root.crl'], ca_issuer_urls: ['http://pki.pure.test/root.crt'] })
    expect(info.key_usages).toEqual(['digital_signature', 'key_cert_sign', 'crl_sign'])
    expect(info.name_constraints).toMatchObject({ critical: true, permitted: { dns: ['pure.test'], ip: [], email: [] }, unsupported: [] })
    expect(info.fingerprint_sha256).toBe(await fingerprint(sub.der))
    expect(info.fingerprint_sha256).toMatch(/^[0-9a-f]{64}$/)

    const crl = await buildCrl({ issuer_certificate: sub.der, signer: subKey.signer, crl_number: 1, this_update: new Date(), next_update: daysFromNow(1), entries: [{ serial: leaf.serial, revoked_at: new Date(), reason: 'superseded' }] })
    const parsed = new x509.X509Crl(crl.der)
    // Pass the key, not the certificate: given a certificate, x509 borrows that certificate's own
    // signature algorithm, which is wrong for an RSA CA under an ECDSA root.
    expect(await parsed.verify({ publicKey: new x509.X509Certificate(sub.der).publicKey })).toBe(true)
    expect(parsed.findRevoked(leaf.serial)?.reason).toBe(x509.X509CrlReason.superseded)

    const p7 = new x509.X509Certificates(buildPkcs7CertsOnly([sub.der, root.der]))
    expect(p7.map((c) => c.subject)).toEqual(['CN=Pure Sub', 'CN=Pure Root'])
  })

  it('round-trips a CA CSR and refuses a tampered one', async () => {
    const key = await caKey('ecdsa-p384')
    const csr = await buildCaCsr({ signer: key.signer, public_key_spki: key.public_key_spki, subject: 'CN=Pure External', path_length: 1, name_constraints: { permitted: { dns: ['pure.test'] } } })
    const parsed = await parseCsr(csr.pem)
    expect(parsed.subject).toBe('CN=Pure External')
    expect(parsed.public_key.spki).toEqual(key.public_key_spki)
    expect(parsed.requested_extensions).toEqual([
      { oid: '2.5.29.19', critical: true },
      { oid: '2.5.29.15', critical: true },
      { oid: '2.5.29.30', critical: true },
      { oid: '2.5.29.14', critical: false },
    ])
    const tampered = new Uint8Array(csr.der)
    tampered[Buffer.from(tampered).indexOf('Pure')] = 'Q'.charCodeAt(0)
    await expect(parseCsr(tampered)).rejects.toMatchObject({ code: 'csr_signature_invalid' })
  })

  it('refuses a CSR signed with a key other than the one it carries', async () => {
    const a = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const b = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: 'CN=mixed', keys: { privateKey: b.privateKey, publicKey: a.publicKey }, signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } })
    await expect(parseCsr(csr.toString('pem'))).rejects.toMatchObject({ code: 'csr_signature_invalid' })
  })

  it('refuses EC keys with encryption key usages and leaves without names', async () => {
    const key = await caKey('ecdsa-p256')
    const root = await buildRootCertificate({ signer: key.signer, public_key_spki: key.public_key_spki, subject: 'CN=Usage Root', not_after: daysFromNow(30) })
    const pair = await generateLeafKeyPair('ecdsa-p256')
    const base = {
      issuer_certificate: root.der,
      signer: key.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      extended_key_usages: ['server_auth' as const],
      not_after: daysFromNow(10),
      crl_urls: [],
      ca_issuer_urls: [],
    }
    await expect(buildLeafCertificate({ ...base, sans: [{ type: 'dns', value: 'a.test' }], key_usages: ['key_encipherment'] })).rejects.toMatchObject({ code: 'invalid_input' })
    await expect(buildLeafCertificate({ ...base, sans: [{ type: 'dns', value: 'a.test' }], key_usages: ['key_cert_sign'] })).rejects.toMatchObject({ code: 'invalid_input' })
    await expect(buildLeafCertificate({ ...base, sans: [], key_usages: ['digital_signature'] })).rejects.toMatchObject({ code: 'invalid_input' })
  })

  it('refuses a signer that asks for a different hash than x509 uses', async () => {
    const key = await caKey('ecdsa-p256')
    const { crypto: adapter, signingKey } = x509Signing(key.signer)
    await expect(adapter.subtle.sign({ name: 'ECDSA', hash: 'SHA-512' } as EcdsaParams, signingKey, new Uint8Array([1]))).rejects.toMatchObject({ code: 'signer_mismatch' })
  })
})

describe('encoding and keys', () => {
  it('round-trips PEM and bundles', async () => {
    const key = await caKey('ecdsa-p256')
    const root = await buildRootCertificate({ signer: key.signer, public_key_spki: key.public_key_spki, subject: 'CN=PEM Root', not_after: daysFromNow(30) })
    const pem = certificateToPem(root.der)
    expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=]{1,64}\n)+-----END CERTIFICATE-----\n$/)
    expect(pemDecodeAll(`junk\n${pem}more junk\n${pem}`).map((b) => b.der)).toEqual([root.der, root.der])
    expect(parseCertificateBundle(pem + pem)).toHaveLength(2)
    expect(() => parseCertificateBundle(`${pem}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`)).toThrow(/only contain certificates/)
  })

  it('describes supported keys and exports a generated leaf key once as PKCS#8 PEM', async () => {
    for (const algorithm of ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048'] as const) {
      const pair = await generateLeafKeyPair(algorithm)
      expect((await describePublicKey(await publicKeySpki(pair.publicKey))).key_algorithm).toBe(algorithm)
      expect(await leafPrivateKeyToPem(pair.privateKey)).toMatch(/^-----BEGIN PRIVATE KEY-----/)
    }
    const p521 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-521' }, true, ['sign'])
    await expect(describePublicKey(await publicKeySpki(p521.publicKey))).rejects.toMatchObject({ code: 'unsupported_key' })
  }, 60_000)
})
