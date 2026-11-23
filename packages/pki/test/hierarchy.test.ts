import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  buildCaCsr,
  buildCertificateBundle,
  buildCrl,
  buildLeafCertificate,
  buildPkcs12,
  buildPkcs7CertsOnly,
  buildRootCertificate,
  generateLeafKeyPair,
  inspectCertificate,
  parseCsr,
  PkiError,
  publicKeySpki,
  signIntermediate,
  validateImportedCaCertificate,
  type IssuedCertificate,
} from '../src/index'
import { caKey, daysFromNow, OPENSSL_VERSION, openssl, opensslKeyId, opensslOk, SKIP_OPENSSL_REASON, tempDir } from './helpers'

const BASE = 'https://pki.example.test/api/pki'

if (!OPENSSL_VERSION) console.warn(`pki hierarchy tests: ${SKIP_OPENSSL_REASON}`)

describe.skipIf(!OPENSSL_VERSION)('CA hierarchy checked with OpenSSL', { timeout: 60_000 }, () => {
  const tmp = tempDir()
  let root: IssuedCertificate
  let l2: IssuedCertificate
  let l3: IssuedCertificate
  let rootKey: Awaited<ReturnType<typeof caKey>>
  let l2Key: Awaited<ReturnType<typeof caKey>>
  let l3Key: Awaited<ReturnType<typeof caKey>>

  beforeAll(async () => {
    rootKey = await caKey('ecdsa-p384')
    l2Key = await caKey('rsa-3072')
    l3Key = await caKey('ecdsa-p256')
    root = await buildRootCertificate({
      signer: rootKey.signer,
      public_key_spki: rootKey.public_key_spki,
      subject: [
        { type: 'CN', value: 'certifly Test Root' },
        { type: 'O', value: 'certifly tests' },
      ],
      not_after: daysFromNow(3650),
      path_length: 2,
    })
    l2 = await signIntermediate({
      issuer_certificate: root.der,
      signer: rootKey.signer,
      public_key_spki: l2Key.public_key_spki,
      subject: 'CN=certifly Test L2, O=certifly tests',
      not_after: daysFromNow(1825),
      path_length: 1,
      name_constraints: { permitted: { dns: ['example.test'], ip: ['10.0.0.0/8'] }, excluded: { dns: ['forbidden.example.test'] } },
      crl_urls: [`${BASE}/crl/root.crl`],
      ca_issuer_urls: [`${BASE}/ca/root.crt`],
    })
    l3 = await signIntermediate({
      issuer_certificate: l2.pem,
      signer: l2Key.signer,
      public_key_spki: l3Key.public_key_spki,
      subject: 'CN=certifly Test L3, O=certifly tests',
      not_after: daysFromNow(730),
      path_length: 0,
      name_constraints: { permitted: { dns: ['svc.example.test'], ip: ['10.1.0.0/16'] } },
      crl_urls: [`${BASE}/crl/l2.crl`],
      ca_issuer_urls: [`${BASE}/ca/l2.crt`],
    })
    tmp.write('root.pem', root.pem)
    tmp.write('l2.pem', l2.pem)
    tmp.write('l3.pem', l3.pem)
    tmp.write('chain.pem', l3.pem + l2.pem)
  })

  afterAll(() => tmp.cleanup())

  const text = (file: string) => opensslOk(['x509', '-in', file, '-noout', '-text'], { cwd: tmp.dir })

  async function leaf(kind: 'server' | 'client') {
    const pair = await generateLeafKeyPair(kind === 'server' ? 'ecdsa-p256' : 'rsa-2048')
    const cert = await buildLeafCertificate({
      issuer_certificate: l3.der,
      signer: l3Key.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      subject: kind === 'server' ? 'CN=api.svc.example.test' : 'CN=client-1, O=certifly tests',
      sans:
        kind === 'server'
          ? [
              { type: 'dns', value: 'api.svc.example.test' },
              { type: 'ip', value: '10.1.2.3' },
            ]
          : [{ type: 'uri', value: 'spiffe://example.test/client-1' }],
      key_usages: kind === 'server' ? ['digital_signature'] : ['digital_signature', 'key_encipherment'],
      extended_key_usages: kind === 'server' ? ['server_auth'] : ['client_auth'],
      not_after: daysFromNow(90),
      crl_urls: [`${BASE}/crl/l3.crl`],
      ca_issuer_urls: [`${BASE}/ca/l3.crt`],
    })
    return { pair, cert }
  }

  it('builds a root that OpenSSL reads with the right extensions', async () => {
    const out = text('root.pem')
    expect(out).toMatch(/X509v3 Basic Constraints: critical\s+CA:TRUE, pathlen:2/)
    expect(out).toMatch(/X509v3 Key Usage: critical\s+Certificate Sign, CRL Sign/)
    expect(out).not.toMatch(/CRL Distribution Points|Authority Information Access|Name Constraints/)
    const info = await inspectCertificate(root.der)
    expect(info.authority_key_identifier).toBe(info.subject_key_identifier)
    expect(out).toContain(opensslKeyId(info.subject_key_identifier!))
    expect(info.serial).toMatch(/^[0-9a-f]{1,40}$/)
    expect(info.self_issued).toBe(true)
  })

  it('builds intermediates with pathLen, name constraints, CDP, AIA and AKI', async () => {
    const out = text('l2.pem')
    expect(out).toMatch(/X509v3 Basic Constraints: critical\s+CA:TRUE, pathlen:1/)
    expect(out).toMatch(/X509v3 Key Usage: critical\s+Digital Signature, Certificate Sign, CRL Sign/)
    expect(out).toMatch(/X509v3 Name Constraints: critical\s+Permitted:\s+DNS:example\.test\s+IP:10\.0\.0\.0\/255\.0\.0\.0\s+Excluded:\s+DNS:forbidden\.example\.test/)
    expect(out).toContain(`URI:${BASE}/crl/root.crl`)
    expect(out).toContain(`CA Issuers - URI:${BASE}/ca/root.crt`)
    const rootInfo = await inspectCertificate(root.pem)
    const l2Info = await inspectCertificate(l2.pem)
    expect(l2Info.authority_key_identifier).toBe(rootInfo.subject_key_identifier)
    expect(out).toMatch(new RegExp(`Authority Key Identifier:\\s+(keyid:)?${opensslKeyId(rootInfo.subject_key_identifier!)}`))
    expect(text('l3.pem')).toMatch(/CA:TRUE, pathlen:0/)
    opensslOk(['verify', '-CAfile', 'root.pem', '-untrusted', 'l2.pem', 'l3.pem'], { cwd: tmp.dir })
  })

  it('issues server and client leaves that openssl verify accepts', async () => {
    const server = await leaf('server')
    const client = await leaf('client')
    tmp.write('server.pem', server.cert.pem)
    tmp.write('client.pem', client.cert.pem)
    opensslOk(['verify', '-CAfile', 'root.pem', '-untrusted', 'chain.pem', '-purpose', 'sslserver', 'server.pem'], { cwd: tmp.dir })
    opensslOk(['verify', '-CAfile', 'root.pem', '-untrusted', 'chain.pem', '-purpose', 'sslclient', 'client.pem'], { cwd: tmp.dir })

    const serverText = text('server.pem')
    expect(serverText).toMatch(/X509v3 Basic Constraints: critical\s+CA:FALSE/)
    expect(serverText).toMatch(/X509v3 Key Usage: critical\s+Digital Signature\n/)
    expect(serverText).toMatch(/X509v3 Extended Key Usage:\s+TLS Web Server Authentication\n/)
    expect(serverText).toMatch(/X509v3 Subject Alternative Name:\s+DNS:api\.svc\.example\.test, IP Address:10\.1\.2\.3/)
    expect(serverText).not.toMatch(/Subject Alternative Name: critical/)
    expect(serverText).toContain(`URI:${BASE}/crl/l3.crl`)
    expect(serverText).toContain(`CA Issuers - URI:${BASE}/ca/l3.crt`)
    const clientText = text('client.pem')
    expect(clientText).toMatch(/Digital Signature, Key Encipherment/)
    expect(clientText).toMatch(/TLS Web Client Authentication/)
    expect(clientText).toContain('URI:spiffe://example.test/client-1')

    const l3Info = await inspectCertificate(l3.der)
    const serverInfo = await inspectCertificate(server.cert.der)
    expect(serverInfo.authority_key_identifier).toBe(l3Info.subject_key_identifier)
    expect(serverInfo.not_before.getTime()).toBeLessThanOrEqual(Date.now() - 4 * 60 * 1000)
    expect(server.cert.not_after_clamped).toBe(false)

    const bundle = buildCertificateBundle(server.cert.der, l3.der, [l2.der, root.der])
    expect(bundle.match(/BEGIN CERTIFICATE/g)).toHaveLength(4)
  })

  it('marks SAN critical when the subject is empty, and clamps notAfter to the issuer', async () => {
    const pair = await generateLeafKeyPair('ecdsa-p384')
    const cert = await buildLeafCertificate({
      issuer_certificate: l3.der,
      signer: l3Key.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      subject: null,
      sans: [{ type: 'dns', value: 'nosubject.svc.example.test' }],
      key_usages: ['digital_signature'],
      extended_key_usages: ['server_auth', 'client_auth'],
      not_after: daysFromNow(5000),
      crl_urls: [],
      ca_issuer_urls: [],
    })
    expect(cert.not_after_clamped).toBe(true)
    expect(cert.not_after.getTime()).toBe((await inspectCertificate(l3.der)).not_after.getTime())
    tmp.write('nosubject.pem', cert.pem)
    expect(text('nosubject.pem')).toMatch(/X509v3 Subject Alternative Name: critical\s+DNS:nosubject\.svc\.example\.test/)
    opensslOk(['verify', '-CAfile', 'root.pem', '-untrusted', 'chain.pem', 'nosubject.pem'], { cwd: tmp.dir })
  })

  it('writes every supported extended key usage, which OpenSSL and inspect name', async () => {
    const pair = await generateLeafKeyPair('ecdsa-p256')
    const all = ['server_auth', 'client_auth', 'code_signing', 'email_protection', 'time_stamping', 'ocsp_signing'] as const
    const cert = await buildLeafCertificate({
      issuer_certificate: l3.der,
      signer: l3Key.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      subject: 'CN=all-ekus.svc.example.test',
      sans: [{ type: 'dns', value: 'all-ekus.svc.example.test' }],
      key_usages: ['digital_signature'],
      extended_key_usages: [...all],
      not_after: daysFromNow(30),
      crl_urls: [],
      ca_issuer_urls: [],
    })
    tmp.write('all-ekus.pem', cert.pem)
    expect(text('all-ekus.pem')).toMatch(
      /X509v3 Extended Key Usage:\s+TLS Web Server Authentication, TLS Web Client Authentication, Code Signing, E-mail Protection, Time Stamping, OCSP Signing\n/,
    )
    const info = await inspectCertificate(cert.der)
    expect(info.extended_key_usage_names).toEqual([...all])
    expect(info.extended_key_usages).toEqual(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.9'])
  })

  it('refuses names outside the issuer name constraints', async () => {
    const pair = await generateLeafKeyPair('ecdsa-p256')
    const base = {
      signer: l3Key.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      key_usages: ['digital_signature'] as const,
      extended_key_usages: ['server_auth'] as const,
      not_after: daysFromNow(30),
      crl_urls: [],
      ca_issuer_urls: [],
    }
    const attempt = (sans: { type: 'dns' | 'ip'; value: string }[], issuer = l3, signer = l3Key.signer) =>
      buildLeafCertificate({ ...base, key_usages: [...base.key_usages], extended_key_usages: [...base.extended_key_usages], issuer_certificate: issuer.der, signer, sans })
    await expect(attempt([{ type: 'dns', value: 'api.elsewhere.test' }])).rejects.toMatchObject({ code: 'name_constraints_violation' })
    await expect(attempt([{ type: 'ip', value: '10.2.0.1' }])).rejects.toMatchObject({ code: 'name_constraints_violation' })
    await expect(attempt([{ type: 'dns', value: 'db.forbidden.example.test' }], l2, l2Key.signer)).rejects.toMatchObject({
      code: 'name_constraints_violation',
      details: { violations: [{ name: 'db.forbidden.example.test', type: 'dns', reason: 'excluded' }] },
    })
  })

  it('refuses intermediates that break pathLen, validity nesting or name constraint subsets', async () => {
    const child = await caKey('ecdsa-p256')
    const base = {
      signer: l2Key.signer,
      public_key_spki: child.public_key_spki,
      subject: 'CN=bad child',
      not_after: daysFromNow(365),
      path_length: 0,
      name_constraints: { permitted: { dns: ['svc.example.test'], ip: ['10.1.0.0/16'] } },
      crl_urls: [],
      ca_issuer_urls: [],
    }
    await expect(signIntermediate({ ...base, issuer_certificate: l3.der, signer: l3Key.signer })).rejects.toMatchObject({ code: 'path_length_exceeded' })
    await expect(signIntermediate({ ...base, issuer_certificate: l2.der, path_length: 1 })).rejects.toMatchObject({ code: 'path_length_exceeded' })
    await expect(signIntermediate({ ...base, issuer_certificate: l2.der, path_length: null })).rejects.toMatchObject({ code: 'path_length_exceeded' })
    await expect(signIntermediate({ ...base, issuer_certificate: l2.der, not_after: daysFromNow(4000) })).rejects.toMatchObject({ code: 'validity_not_nested' })
    await expect(
      signIntermediate({ ...base, issuer_certificate: l2.der, name_constraints: { permitted: { dns: ['example.test', 'other.test'], ip: ['10.0.0.0/8'] } } }),
    ).rejects.toMatchObject({ code: 'name_constraints_not_subset' })
    // The signer must hold the parent's key.
    await expect(signIntermediate({ ...base, issuer_certificate: l2.der, signer: l3Key.signer })).rejects.toMatchObject({ code: 'signer_mismatch' })
  })

  it('builds a CRL that OpenSSL reads, and verify -crl_check rejects the revoked leaf', async () => {
    const revoked = await leaf('server')
    const good = await leaf('client')
    const crl = await buildCrl({
      issuer_certificate: l3.der,
      signer: l3Key.signer,
      crl_number: 7,
      this_update: new Date(Date.now() - 60_000),
      next_update: daysFromNow(7),
      entries: [{ serial: revoked.cert.serial, revoked_at: new Date(Date.now() - 30_000), reason: 'key_compromise' }],
    })
    expect(crl.next_update_clamped).toBe(false)
    tmp.write('l3.crl.pem', crl.pem)
    tmp.write('revoked.pem', revoked.cert.pem)
    tmp.write('good.pem', good.cert.pem)
    const out = opensslOk(['crl', '-in', 'l3.crl.pem', '-noout', '-text'], { cwd: tmp.dir })
    expect(out).toMatch(/X509v3 CRL Number:\s+7/)
    expect(out).toMatch(/X509v3 Authority Key Identifier:/)
    expect(out.toLowerCase()).toContain(`serial number: ${revoked.cert.serial}`)
    expect(out).toMatch(/X509v3 CRL Reason Code:\s+Key Compromise/)
    opensslOk(['crl', '-in', 'l3.crl.pem', '-noout', '-CAfile', 'l3.pem'], { cwd: tmp.dir })

    const check = (file: string) => openssl(['verify', '-crl_check', '-CAfile', 'root.pem', '-untrusted', 'chain.pem', '-CRLfile', 'l3.crl.pem', file], { cwd: tmp.dir })
    const rejected = check('revoked.pem')
    expect(rejected.status).not.toBe(0)
    expect(rejected.stdout + rejected.stderr).toMatch(/certificate revoked/)
    expect(check('good.pem').status).toBe(0)
  })

  it('clamps nextUpdate to the issuer and refuses duplicate serials', async () => {
    const crl = await buildCrl({
      issuer_certificate: l3.der,
      signer: l3Key.signer,
      crl_number: 8n,
      this_update: new Date(),
      next_update: daysFromNow(5000),
      entries: [],
    })
    expect(crl.next_update_clamped).toBe(true)
    await expect(
      buildCrl({
        issuer_certificate: l3.der,
        signer: l3Key.signer,
        crl_number: 9,
        this_update: new Date(),
        next_update: daysFromNow(1),
        entries: [
          { serial: '0abc', revoked_at: new Date() },
          { serial: 'abc', revoked_at: new Date() },
        ],
      }),
    ).rejects.toMatchObject({ code: 'invalid_crl' })
  })

  it('exports PKCS#12 with AES-256-CBC, PBKDF2-SHA-256 and an HMAC-SHA-256 MAC', async () => {
    const { pair, cert } = await leaf('client')
    const p12 = await buildPkcs12({ private_key: pair.privateKey, certificate: cert.der, chain: [l3.der, l2.der, root.der], password: 'correct horse', friendly_name: 'client-1' })
    tmp.write('client.p12', p12)
    const info = opensslOk(['pkcs12', '-in', 'client.p12', '-info', '-noout', '-passin', 'pass:correct horse'], { cwd: tmp.dir })
    expect(info).toMatch(/MAC: sha256/)
    expect(info).toMatch(/Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 100000, PRF hmacWithSHA256/)
    expect(info).toMatch(/PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 100000, PRF hmacWithSHA256/)
    const certs = opensslOk(['pkcs12', '-in', 'client.p12', '-nokeys', '-passin', 'pass:correct horse'], { cwd: tmp.dir })
    expect(certs.match(/BEGIN CERTIFICATE/g)).toHaveLength(4)
    expect(certs).toContain('friendlyName: client-1')
    const keys = opensslOk(['pkcs12', '-in', 'client.p12', '-nocerts', '-noenc', '-passin', 'pass:correct horse'], { cwd: tmp.dir })
    expect(keys).toContain('BEGIN PRIVATE KEY')
    expect(openssl(['pkcs12', '-in', 'client.p12', '-info', '-noout', '-passin', 'pass:wrong'], { cwd: tmp.dir }).status).not.toBe(0)
    await expect(buildPkcs12({ private_key: pair.privateKey, certificate: cert.der, password: '' })).rejects.toMatchObject({ code: 'invalid_password' })
  })

  it('builds a PKCS#7 certs-only bundle', () => {
    tmp.write('cacerts.p7', buildPkcs7CertsOnly([l3.der, l2.der, root.der]))
    const out = opensslOk(['pkcs7', '-inform', 'DER', '-in', 'cacerts.p7', '-print_certs', '-noout'], { cwd: tmp.dir })
    expect(out).toMatch(/subject=.*certifly Test L3/)
    expect(out).toMatch(/subject=.*certifly Test L2/)
    expect(out).toMatch(/subject=.*certifly Test Root/)
  })
})

describe.skipIf(!OPENSSL_VERSION)('externally signed CA checked with OpenSSL', { timeout: 60_000 }, () => {
  const tmp = tempDir()
  const subject = 'CN=certifly External L2, O=certifly tests'
  const constraints = { permitted: { dns: ['ext.example.test'] } }
  let key: Awaited<ReturnType<typeof caKey>>

  beforeAll(async () => {
    opensslOk(
      [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-384', '-noenc',
        '-keyout', 'ext-root.key', '-out', 'ext-root.pem', '-days', '3650', '-subj', '/CN=OpenSSL Test Root',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
      ],
      { cwd: tmp.dir },
    )
    key = await caKey('ecdsa-p384')
  })

  afterAll(() => tmp.cleanup())

  /** Signs a CSR with the OpenSSL root the way an offline root operator would. */
  function signWithRoot(csrPem: string, name: string, extensions: string): string {
    tmp.write(`${name}.csr`, csrPem)
    tmp.write(`${name}.ext`, `[v3_ca]\n${extensions}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n`)
    opensslOk(
      ['x509', '-req', '-in', `${name}.csr`, '-CA', 'ext-root.pem', '-CAkey', 'ext-root.key', '-set_serial', '0x1234' + Math.floor(Math.random() * 1e6), '-days', '1825', '-extfile', `${name}.ext`, '-extensions', 'v3_ca', '-out', `${name}.pem`],
      { cwd: tmp.dir },
    )
    return opensslOk(['x509', '-in', `${name}.pem`], { cwd: tmp.dir })
  }

  const good = 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\nnameConstraints=critical,permitted;DNS:ext.example.test'

  it('creates a CA CSR that requests the CA extensions', async () => {
    const csr = await buildCaCsr({ signer: key.signer, public_key_spki: key.public_key_spki, subject, path_length: 0, name_constraints: constraints })
    tmp.write('ext.csr.pem', csr.pem)
    const out = opensslOk(['req', '-in', 'ext.csr.pem', '-noout', '-text', '-verify'], { cwd: tmp.dir })
    expect(out).toMatch(/verify OK|Certificate request self-signature verify OK/)
    expect(out).toMatch(/X509v3 Basic Constraints: critical\s+CA:TRUE, pathlen:0/)
    expect(out).toMatch(/X509v3 Key Usage: critical\s+Digital Signature, Certificate Sign, CRL Sign/)
    expect(out).toMatch(/X509v3 Name Constraints: critical\s+Permitted:\s+DNS:ext\.example\.test/)
    expect(out).toMatch(/X509v3 Subject Key Identifier/)
    const parsed = await parseCsr(csr.pem)
    expect(parsed.public_key.key_algorithm).toBe('ecdsa-p384')
  })

  it('accepts the certificate signed by the OpenSSL root, and an L3 signed in certifly verifies', async () => {
    const csr = await buildCaCsr({ signer: key.signer, public_key_spki: key.public_key_spki, subject, path_length: 0, name_constraints: constraints })
    const certPem = signWithRoot(csr.pem, 'ext-l2', good)
    const rootPem = opensslOk(['x509', '-in', 'ext-root.pem'], { cwd: tmp.dir })
    const result = await validateImportedCaCertificate(certPem, rootPem, { public_key_spki: key.public_key_spki, path_length: 0, subject })
    expect(result.errors).toEqual([])
    expect(result.ok).toBe(true)
    expect(result.chain).toHaveLength(1)
    expect(result.chain_pem).toContain('BEGIN CERTIFICATE')

    // The imported CA issues a leaf; OpenSSL must accept the whole path.
    const pair = await generateLeafKeyPair('ecdsa-p256')
    const issued = await buildLeafCertificate({
      issuer_certificate: certPem,
      signer: key.signer,
      public_key_spki: await publicKeySpki(pair.publicKey),
      subject: 'CN=www.ext.example.test',
      sans: [{ type: 'dns', value: 'www.ext.example.test' }],
      key_usages: ['digital_signature'],
      extended_key_usages: ['server_auth'],
      not_after: daysFromNow(30),
      crl_urls: [`${BASE}/crl/ext-l2.crl`],
      ca_issuer_urls: [`${BASE}/ca/ext-l2.crt`],
    })
    tmp.write('ext-leaf.pem', issued.pem)
    opensslOk(['verify', '-CAfile', 'ext-root.pem', '-untrusted', 'ext-l2.pem', 'ext-leaf.pem'], { cwd: tmp.dir })
  })

  it('accepts an internal L3 under an externally signed L2 with pathLen 1', async () => {
    const l2 = await caKey('ecdsa-p256')
    const csr = await buildCaCsr({ signer: l2.signer, public_key_spki: l2.public_key_spki, subject, path_length: 1, name_constraints: constraints })
    const certPem = signWithRoot(csr.pem, 'ext-l2b', good.replace('pathlen:0', 'pathlen:1'))
    const rootPem = opensslOk(['x509', '-in', 'ext-root.pem'], { cwd: tmp.dir })
    expect((await validateImportedCaCertificate(certPem, [rootPem], { public_key_spki: l2.public_key_spki, path_length: 1, subject })).ok).toBe(true)
    const l3 = await caKey('ecdsa-p256')
    const l3Cert = await signIntermediate({
      issuer_certificate: certPem,
      signer: l2.signer,
      public_key_spki: l3.public_key_spki,
      subject: 'CN=certifly External L3',
      not_after: daysFromNow(365),
      path_length: 0,
      name_constraints: { permitted: { dns: ['team.ext.example.test'] } },
      crl_urls: [`${BASE}/crl/ext-l2b.crl`],
      ca_issuer_urls: [`${BASE}/ca/ext-l2b.crt`],
    })
    tmp.write('ext-l3.pem', l3Cert.pem)
    opensslOk(['verify', '-CAfile', 'ext-root.pem', '-untrusted', 'ext-l2b.pem', 'ext-l3.pem'], { cwd: tmp.dir })
  })

  it.each([
    ['wrong key', 'public_key_mismatch', good],
    ['wrong pathLen', 'path_length_mismatch', good.replace('pathlen:0', 'pathlen:1')],
    ['missing name constraints', 'name_constraints_missing', good.split('\n').slice(0, 2).join('\n')],
    ['missing cRLSign', 'missing_crl_sign', good.replace('keyCertSign,cRLSign', 'keyCertSign')],
  ] as const)('rejects a certificate with a %s', async (name, code, extensions) => {
    const other = name === 'wrong key' ? await caKey('ecdsa-p384') : key
    const csr = await buildCaCsr({ signer: other.signer, public_key_spki: other.public_key_spki, subject, path_length: 0, name_constraints: constraints })
    const certPem = signWithRoot(csr.pem, `bad-${code}`, extensions)
    const rootPem = opensslOk(['x509', '-in', 'ext-root.pem'], { cwd: tmp.dir })
    const result = await validateImportedCaCertificate(certPem, rootPem, { public_key_spki: key.public_key_spki, path_length: 0, subject })
    expect(result.ok).toBe(false)
    expect(result.errors.map((e) => e.code)).toContain(code)
    expect(result.chain).toEqual([])
  })

  it('rejects a wrong subject and a chain without its root', async () => {
    const csr = await buildCaCsr({ signer: key.signer, public_key_spki: key.public_key_spki, subject, path_length: 0, name_constraints: constraints })
    const certPem = signWithRoot(csr.pem, 'ext-l2c', good)
    const wrongSubject = await validateImportedCaCertificate(certPem, opensslOk(['x509', '-in', 'ext-root.pem'], { cwd: tmp.dir }), {
      public_key_spki: key.public_key_spki,
      path_length: 0,
      subject: 'CN=Someone Else',
    })
    expect(wrongSubject.errors.map((e) => e.code)).toEqual(['subject_mismatch'])
    const noRoot = await validateImportedCaCertificate(certPem, [], { public_key_spki: key.public_key_spki, path_length: 0, subject })
    expect(noRoot.errors.map((e) => e.code)).toEqual(['chain_incomplete'])
  })
})

describe.skipIf(!OPENSSL_VERSION)('CSR parsing checked against OpenSSL', { timeout: 60_000 }, () => {
  const tmp = tempDir()
  afterAll(() => tmp.cleanup())

  const csrFrom = (args: string[]) => {
    opensslOk(['req', '-new', '-noenc', '-keyout', 'k.pem', '-out', 'r.pem', '-subj', '/CN=app.example.test/O=Acme', ...args], { cwd: tmp.dir })
    return opensslOk(['req', '-in', 'r.pem'], { cwd: tmp.dir })
  }

  it('reads subject, SANs, key and requested extensions from an OpenSSL CSR', async () => {
    const pem = csrFrom(['-newkey', 'rsa:2048', '-addext', 'subjectAltName=DNS:app.example.test,IP:10.0.0.1,email:ops@example.test,URI:spiffe://example.test/app', '-addext', 'keyUsage=critical,keyCertSign'])
    const csr = await parseCsr(pem)
    expect(csr.subject_attributes).toEqual([
      { type: 'CN', value: 'app.example.test' },
      { type: 'O', value: 'Acme' },
    ])
    expect(csr.sans).toEqual([
      { type: 'dns', value: 'app.example.test' },
      { type: 'ip', value: '10.0.0.1' },
      { type: 'email', value: 'ops@example.test' },
      { type: 'uri', value: 'spiffe://example.test/app' },
    ])
    expect(csr.public_key).toMatchObject({ type: 'rsa', bits: 2048, key_algorithm: 'rsa-2048' })
    expect(csr.signature_algorithm).toBe('RSASSA-PKCS1-v1_5/SHA-256')
    // Reported, but certifly never copies KU/EKU from a CSR.
    expect(csr.requested_extensions.map((e) => e.oid)).toEqual(['2.5.29.17', '2.5.29.15'])
  })

  it.each([
    ['RSA 1024', ['-newkey', 'rsa:1024']],
    ['P-521', ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-521']],
    ['Ed25519', ['-newkey', 'ed25519']],
  ])('refuses a %s key', async (_name, args) => {
    await expect(parseCsr(csrFrom(args))).rejects.toMatchObject({ code: 'unsupported_key' })
  })

  it('refuses a CSR whose signature does not verify', async () => {
    const pem = csrFrom(['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'])
    const der = new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64'))
    // Change one letter of the subject: the request still parses, but the signature no longer matches.
    const at = Buffer.from(der).indexOf('app.example.test')
    der[at] = 'b'.charCodeAt(0)
    await expect(parseCsr(der)).rejects.toBeInstanceOf(PkiError)
    await expect(parseCsr(der)).rejects.toMatchObject({ code: 'csr_signature_invalid' })
  })
})
