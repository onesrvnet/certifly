import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, Client, query, resetState, serverOptions, setupAdmin } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('certificate tests: the openssl CLI is not installed, so the OpenSSL checks are skipped')

const none = { dns: [], ip: [], email: [] }
const DAY = 86400

/** A scratch directory for OpenSSL, with a runner that fails the test on errors. */
function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-cert-test-'))
  const run = (args: string[], input?: string) => {
    const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8', input })
    if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
    return result.stdout + result.stderr
  }
  const write = (name: string, data: string | Uint8Array) => writeFileSync(join(dir, name), data)
  return { dir, run, write, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

async function download(path: string) {
  const response = await new Client().get(path)
  return new Uint8Array(await response.arrayBuffer())
}

async function ok(client: Client, method: string, body: object) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

/** A free TCP port on the loopback interface. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      server.close(() => (typeof address === 'object' && address ? resolve(address.port) : reject(new Error('no port'))))
    })
  })
}

/**
 * A root, an issuing CA below it limited to example.test, localhost and two IP ranges, a server
 * template and a client template on it, and an admin, operator (with an API key) and viewer.
 */
async function world() {
  const admin = await setupAdmin()
  const operator = await addUser(admin, 'op@example.com', 'operator')
  const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
  const operatorKey = (await operator.rpc('api_keys.create', { name: 'automation' })).body.data.secret as string
  const root = await ok(admin, 'certificate_authorities.create', {
    signing: 'self_signed',
    name: 'Root',
    slug: 'root',
    subject: [{ type: 'CN', value: 'Test Root' }],
    validity_days: 3650,
    path_length: 1,
  })
  const issuing = await ok(admin, 'certificate_authorities.create', {
    signing: 'internal',
    parent_ca_id: root.id,
    name: 'Issuing',
    slug: 'issuing',
    subject: [{ type: 'CN', value: 'Test Issuing CA' }],
    validity_days: 365,
    path_length: 0,
    name_constraints: { permitted: { ...none, dns: ['example.test', 'localhost'], ip: ['10.0.0.0/8', '127.0.0.0/8'] }, excluded: none },
  })
  const server = await ok(admin, 'templates.create', {
    preset: 'webserver_tls',
    name: 'Web',
    slug: 'web',
    ca_id: issuing.id,
    allowed_san_types: ['dns', 'ip'],
    allowed_dns: ['example.test', '**.example.test', 'localhost'],
    allowed_ips: ['10.0.0.0/8', '127.0.0.0/8'],
    max_ttl_seconds: 90 * DAY,
    default_ttl_seconds: 30 * DAY,
  })
  const client = await ok(admin, 'templates.create', { preset: 'mtls_client', name: 'Clients', slug: 'clients', ca_id: issuing.id, allowed_dns: ['example.test', '**.example.test'] })
  return { admin, operator, viewer, operatorKey, root, issuing, server, client }
}

const keygen = (format: 'pem' | 'pkcs12' = 'pem', pkcs12_password?: string) => ({ algorithm: 'ecdsa-p256', format, ...(pkcs12_password ? { pkcs12_password } : {}) })

describe('certificates', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  describe('permissions', () => {
    it('refuses viewers, and lets operators issue and renew, also with an API key', async () => {
      const w = await world()
      const body = { template_id: w.server.id, keygen: keygen(), sans: [{ type: 'dns', value: 'app.example.test' }] }
      const asViewer = await w.viewer.rpc('certificates.issue', body)
      expect(asViewer).toMatchObject({ status: 403, body: { error: { code: 'forbidden' } } })

      const asOperator = await w.operator.rpc('certificates.issue', body)
      expect(asOperator.status).toBe(200)
      expect(asOperator.body.data.certificate).toMatchObject({ source: 'ui', status: 'active', requested_by_api_key_id: null, permissions: { read: true, renew: true } })

      const viaKey = await new Client().rpcWithKey(w.operatorKey, 'certificates.issue', body)
      expect(viaKey.status).toBe(200)
      expect(viaKey.body.data.certificate.source).toBe('api')
      expect(viaKey.body.data.certificate.requested_by_api_key_id).not.toBeNull()

      const id = asOperator.body.data.certificate.id
      expect((await w.viewer.rpc('certificates.renew', { id, keygen: keygen() })).status).toBe(403)
      expect((await w.viewer.rpc('certificates.get', { id })).body.data.permissions).toEqual({ read: true, update_tags: false, renew: false, revoke: false })
      expect((await new Client().rpcWithKey(w.operatorKey, 'certificates.renew', { id, keygen: keygen() })).status).toBe(200)
      expect((await w.viewer.rpc('certificates.list')).body.data).toHaveLength(3)
      expect((await w.viewer.rpc('certificates.get', { id: crypto.randomUUID() })).status).toBe(404)
    })
  })

  describe('rules', () => {
    it('refuses what the template does not allow', async () => {
      const w = await world()
      const issue = (body: object) => w.operator.rpc('certificates.issue', { template_id: w.server.id, keygen: keygen(), ...body })
      const code = async (body: object) => (await issue(body)).body.error?.code

      const outside = await issue({ sans: [{ type: 'dns', value: 'app.example.test' }, { type: 'dns', value: 'www.other.test' }] })
      expect(outside.status).toBe(400)
      expect(outside.body.error).toMatchObject({ code: 'san_not_allowed', details: { violations: [{ san: 'dns:www.other.test', reason: 'san_not_allowed' }] } })
      expect(await code({ sans: [{ type: 'dns', value: '*.example.test' }] })).toBe('wildcard_not_allowed')
      expect(await code({ sans: [{ type: 'email', value: 'ops@example.test' }] })).toBe('san_type_not_allowed')
      expect(await code({ sans: [] })).toBe('san_required')
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }], ttl_seconds: 91 * DAY })).toBe('ttl_exceeds_maximum')
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }], keygen: keygen('pkcs12', 'short') })).toBe('pkcs12_password_too_short')
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }], keygen: { algorithm: 'ecdsa-p256', format: 'pem', pkcs12_password: 'a-long-password' } })).toBe('pkcs12_password_unexpected')
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }], common_name: 'www.other.test' })).toBe('common_name_not_allowed')
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }], csr: 'not a csr' })).toBe('csr_or_keygen')

      // The client template needs a CN; URI hosts and email domains follow its domain patterns.
      const client = (body: object) => w.operator.rpc('certificates.issue', { template_id: w.client.id, keygen: keygen(), ...body })
      expect((await client({})).body.error.code).toBe('common_name_required')
      expect((await client({ common_name: 'device-1', sans: [{ type: 'uri', value: 'spiffe://elsewhere.test/x' }] })).body.error.code).toBe('san_not_allowed')
      expect((await client({ common_name: 'device-1', sans: [{ type: 'uri', value: 'spiffe://example.test/device-1' }, { type: 'email', value: 'dev@example.test' }] })).status).toBe(200)

      // No keygen unless the template allows it.
      await ok(w.admin, 'templates.update', { id: w.server.id, allow_server_keygen: false })
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }] })).toBe('keygen_not_allowed')

      // Nothing from an archived template or a disabled CA.
      await ok(w.admin, 'templates.archive', { id: w.client.id })
      expect((await client({ common_name: 'device-2' })).body.error.code).toBe('template_archived')
      await ok(w.admin, 'templates.update', { id: w.server.id, allow_server_keygen: true })
      await ok(w.admin, 'certificate_authorities.archive', { id: w.issuing.id })
      expect(await code({ sans: [{ type: 'dns', value: 'a.example.test' }] })).toBe('ca_disabled')
      const [{ n }] = await query()`select count(*)::int as n from certificates`
      expect(n).toBe(1)
    })

    it('reports when notAfter is cut back to the CA’s end', async () => {
      const w = await world()
      await ok(w.admin, 'templates.update', { id: w.server.id, max_ttl_seconds: 400 * DAY })
      const res = await ok(w.operator, 'certificates.issue', { template_id: w.server.id, keygen: keygen(), sans: [{ type: 'dns', value: 'long.example.test' }], ttl_seconds: 400 * DAY })
      expect(res.not_after_clamped).toBe(true)
      expect(res.certificate.not_after).toBe(w.issuing.not_after)
    })
  })

  describe.skipIf(!hasOpenssl)('with OpenSSL', () => {
    const tmp = scratch()
    afterAll(() => tmp.cleanup())

    /** The root as PEM and the issuing CA, from the public endpoints. */
    async function trust() {
      tmp.write('root.der', await download('/api/pki/ca/root.crt'))
      tmp.run(['x509', '-inform', 'DER', '-in', 'root.der', '-out', 'root.pem'])
      const chain = new TextDecoder().decode(await download('/api/pki/ca/issuing/chain.pem'))
      tmp.write('issuing.pem', chain.split(/(?<=-----END CERTIFICATE-----\n)/)[0]!)
      tmp.write('cas.pem', chain)
    }

    it('issues for openssl CSRs (P-256 and RSA-2048) with the template’s usages, whatever the CSR asks for', async () => {
      const w = await world()
      await trust()
      for (const [name, keyArgs, usage] of [
        ['ec', ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'], /X509v3 Key Usage: critical\s+Digital Signature\n/],
        ['rsa', ['-newkey', 'rsa:2048'], /X509v3 Key Usage: critical\s+Digital Signature, Key Encipherment\n/],
      ] as const) {
        tmp.run([
          'req', '-new', ...keyArgs, '-noenc', '-keyout', `${name}.key`, '-out', `${name}.csr`,
          '-subj', `/CN=${name}.example.test/O=Ignored Org`,
          '-addext', `subjectAltName=DNS:${name}.example.test,IP:10.1.2.3`,
          // A CSR may ask for anything; certifly takes key usage and EKU from the template only.
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
          '-addext', 'extendedKeyUsage=codeSigning',
          '-addext', 'basicConstraints=critical,CA:TRUE',
        ])
        const csr = tmp.run(['req', '-in', `${name}.csr`])
        const res = await w.operator.rpc('certificates.issue', { template_id: w.server.id, csr })
        expect(res.status).toBe(200)
        expect(res.headers.get('cache-control')).toBe('no-store')
        const { certificate, private_key, ignored_subject_fields } = res.body.data
        expect(private_key).toBeNull()
        expect(ignored_subject_fields).toEqual(['O'])
        expect(certificate).toMatchObject({
          common_name: `${name}.example.test`,
          subject_dn: `CN=${name}.example.test`,
          key_algorithm: name === 'ec' ? 'ecdsa-p256' : 'rsa-2048',
          sans: [{ type: 'dns', value: `${name}.example.test` }, { type: 'ip', value: '10.1.2.3' }],
          extended_key_usages: ['server_auth'],
          has_csr: true,
        })
        expect(certificate.bundle_pem).toBe(certificate.pem + certificate.chain_pem)

        tmp.write(`${name}.pem`, certificate.pem)
        expect(tmp.run(['verify', '-CAfile', 'root.pem', '-untrusted', 'issuing.pem', '-purpose', 'sslserver', `${name}.pem`])).toContain(`${name}.pem: OK`)
        const text = tmp.run(['x509', '-in', `${name}.pem`, '-noout', '-text'])
        expect(text).toMatch(usage)
        expect(text).toMatch(/X509v3 Extended Key Usage:\s+TLS Web Server Authentication\n/)
        expect(text).toMatch(new RegExp(`X509v3 Subject Alternative Name:\\s+DNS:${name}\\.example\\.test, IP Address:10\\.1\\.2\\.3`))
        expect(text).toMatch(/X509v3 Basic Constraints: critical\s+CA:FALSE/)
        expect(text).not.toMatch(/Code Signing|Certificate Sign/)
        const key = w.issuing.versions[0].key_id
        expect(text).toContain(`URI:${process.env.URL}/api/pki/crl/issuing/${key}.crl`)
        expect(text).toContain(`CA Issuers - URI:${process.env.URL}/api/pki/ca/issuing/${key}.crt`)
        // The private key that goes with it is the requester's own.
        expect(tmp.run(['x509', '-in', `${name}.pem`, '-noout', '-pubkey'])).toBe(tmp.run(['pkey', '-in', `${name}.key`, '-pubout']))
      }
    })

    it('refuses a CSR whose signature does not verify, and keys the template does not allow', async () => {
      const w = await world()
      tmp.run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'bad.key', '-out', 'bad.csr', '-outform', 'DER', '-subj', '/CN=bad.example.test', '-addext', 'subjectAltName=DNS:bad.example.test'])
      const der = new Uint8Array(readFileSync(join(tmp.dir, 'bad.csr')))
      // Flip a bit in the requested name: the structure stays valid, the signature no longer matches.
      const at = Buffer.from(der).indexOf(Buffer.from('bad.example.test'))
      der[at] ^= 0x01
      const pem = `-----BEGIN CERTIFICATE REQUEST-----\n${Buffer.from(der).toString('base64').replace(/.{64}/g, '$&\n')}\n-----END CERTIFICATE REQUEST-----\n`
      const forged = await w.operator.rpc('certificates.issue', { template_id: w.server.id, csr: pem, sans: [{ type: 'dns', value: 'bad.example.test' }] })
      expect(forged).toMatchObject({ status: 400, body: { error: { code: 'csr_signature_invalid' } } })

      await ok(w.admin, 'templates.update', { id: w.server.id, key_algorithms: ['ecdsa-p384'] })
      tmp.run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'p256.key', '-out', 'p256.csr', '-subj', '/CN=p256.example.test', '-addext', 'subjectAltName=DNS:p256.example.test'])
      const p256 = await w.operator.rpc('certificates.issue', { template_id: w.server.id, csr: tmp.run(['req', '-in', 'p256.csr']) })
      expect(p256.body.error.code).toBe('key_algorithm_not_allowed')
      const [{ n }] = await query()`select count(*)::int as n from certificates`
      expect(n).toBe(0)
    })

    it('returns a generated key once, as PEM or as a PKCS#12 that openssl opens, and stores no secret', async () => {
      const w = await world()
      const password = 'correct horse battery staple'
      const pem = await ok(w.operator, 'certificates.issue', { template_id: w.server.id, keygen: keygen(), sans: [{ type: 'dns', value: 'gen.example.test' }] })
      expect(pem.private_key.format).toBe('pem')
      expect(pem.private_key.pem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/)
      expect(pem.certificate.key_generated).toBe(true)
      tmp.write('gen.key', pem.private_key.pem)
      tmp.write('gen.pem', pem.certificate.pem)
      expect(tmp.run(['x509', '-in', 'gen.pem', '-noout', '-pubkey'])).toBe(tmp.run(['pkey', '-in', 'gen.key', '-pubout']))

      const again = await w.operator.rpc('certificates.get', { id: pem.certificate.id })
      expect(again.status).toBe(200)
      expect(again.body.data).not.toHaveProperty('private_key')
      expect(JSON.stringify(again.body)).not.toContain('PRIVATE KEY')

      const rsa = await ok(w.operator, 'certificates.issue', {
        template_id: w.server.id,
        keygen: { algorithm: 'rsa-2048', format: 'pkcs12', pkcs12_password: password },
        sans: [{ type: 'dns', value: 'p12.example.test' }],
      })
      expect(rsa.private_key.format).toBe('pkcs12')
      tmp.write('gen.p12', Buffer.from(rsa.private_key.pkcs12_base64, 'base64'))
      const opened = tmp.run(['pkcs12', '-in', 'gen.p12', '-passin', `pass:${password}`, '-noenc'])
      expect(opened).toContain('BEGIN PRIVATE KEY')
      expect(opened.match(/BEGIN CERTIFICATE/g)).toHaveLength(3)
      const wrong = spawnSync('openssl', ['pkcs12', '-in', 'gen.p12', '-passin', 'pass:wrong password!', '-noenc'], { cwd: tmp.dir })
      expect(wrong.status).not.toBe(0)

      // Nothing secret in the audit log or the certificate rows.
      const keyBody = pem.private_key.pem.split('\n')[1]!
      const [{ events }] = await query()`select coalesce(string_agg(data::text, ' '), '') as events from events`
      const [{ rows }] = await query()`select coalesce(string_agg(row_to_json(c)::text, ' '), '') as rows from certificates c`
      for (const dump of [events, rows]) {
        expect(dump).not.toContain('PRIVATE KEY')
        expect(dump).not.toContain(keyBody)
        expect(dump).not.toContain(password)
        expect(dump).not.toContain(rsa.private_key.pkcs12_base64.slice(0, 40))
      }
      expect(events).toContain(pem.certificate.serial)
      const names = (await w.admin.rpc('events.list', { subject_type: 'certificate' })).body.data.map((e: { name: string }) => e.name)
      expect(names).toEqual(['certificates.issue', 'certificates.issue'])
    })

    it('renews: the new certificate supersedes the old one', async () => {
      const w = await world()
      tmp.run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'renew.key', '-out', 'renew.csr', '-subj', '/CN=renew.example.test', '-addext', 'subjectAltName=DNS:renew.example.test'])
      const first = await ok(w.operator, 'certificates.issue', { template_id: w.server.id, csr: tmp.run(['req', '-in', 'renew.csr']) })
      const old = first.certificate

      // Reuses the stored CSR: same key, subject and SANs, a new serial.
      const renewed = await ok(w.operator, 'certificates.renew', { id: old.id })
      const next = renewed.certificate
      expect(next.id).not.toBe(old.id)
      expect(next.serial).not.toBe(old.serial)
      expect(next).toMatchObject({ subject_dn: old.subject_dn, sans: old.sans, template_id: old.template_id, supersedes_id: old.id, status: 'active' })
      tmp.write('renewed.pem', next.pem)
      expect(tmp.run(['x509', '-in', 'renewed.pem', '-noout', '-pubkey'])).toBe(tmp.run(['pkey', '-in', 'renew.key', '-pubout']))

      const before = (await w.operator.rpc('certificates.get', { id: old.id })).body.data
      expect(before).toMatchObject({ status: 'superseded', superseded_by_id: next.id, permissions: { renew: false } })
      expect((await w.operator.rpc('certificates.renew', { id: old.id })).body.error.code).toBe('certificate_not_renewable')
      expect((await w.operator.rpc('certificates.list', { status: 'superseded' })).body.data.map((c: { id: string }) => c.id)).toEqual([old.id])

      // A certificate whose key certifly generated renews with a new key.
      const generated = await ok(w.operator, 'certificates.issue', { template_id: w.server.id, keygen: keygen(), sans: [{ type: 'dns', value: 'gen.example.test' }] })
      expect((await w.operator.rpc('certificates.renew', { id: generated.certificate.id })).body.error.code).toBe('csr_or_keygen')
      const rekeyed = await ok(w.operator, 'certificates.renew', { id: generated.certificate.id, keygen: keygen() })
      expect(rekeyed.private_key.pem).toMatch(/BEGIN PRIVATE KEY/)
      expect(rekeyed.private_key.pem).not.toBe(generated.private_key.pem)

      const events = (await w.admin.rpc('events.list', { name: 'certificates.renew' })).body.data
      expect(events.map((e: { subject_id: string; data: { previous_certificate_id: string } }) => [e.subject_id, e.data.previous_certificate_id])).toEqual([
        [rekeyed.certificate.id, generated.certificate.id],
        [next.id, old.id],
      ])
    })

    it('lists with filters and search, and counts for the dashboard', async () => {
      const w = await world()
      const a = await ok(w.operator, 'certificates.issue', { template_id: w.server.id, keygen: keygen(), sans: [{ type: 'dns', value: 'alpha.example.test' }], ttl_seconds: 5 * DAY })
      const b = await ok(w.operator, 'certificates.issue', { template_id: w.client.id, keygen: keygen(), common_name: 'bravo-device' })
      await query()`update certificates set not_before = now() - interval '2 days', not_after = now() - interval '1 day' where id = ${b.certificate.id}`

      const ids = async (body: object) => (await w.viewer.rpc('certificates.list', body)).body.data.map((c: { id: string }) => c.id)
      expect(await ids({})).toEqual([b.certificate.id, a.certificate.id])
      expect(await ids({ status: 'active' })).toEqual([a.certificate.id])
      expect(await ids({ status: 'expired' })).toEqual([b.certificate.id])
      expect(await ids({ template_id: w.client.id })).toEqual([b.certificate.id])
      expect(await ids({ query: 'alpha' })).toEqual([a.certificate.id])
      expect(await ids({ query: 'BRAVO' })).toEqual([b.certificate.id])
      expect(await ids({ query: a.certificate.serial.slice(0, 8) })).toEqual([a.certificate.id])
      expect(await ids({ expiring_before: new Date(Date.now() + 7 * DAY * 1000).toISOString(), status: 'active' })).toEqual([a.certificate.id])
      expect(await ids({ order: 'expiry' })).toEqual([b.certificate.id, a.certificate.id])
      expect(await ids({ source: 'api' })).toEqual([])
      const page = await w.viewer.rpc('certificates.list', { limit: 1 })
      expect(page.body.next_cursor).toBeTruthy()
      expect(await ids({ limit: 1, cursor: page.body.next_cursor })).toEqual([a.certificate.id])

      expect((await w.viewer.rpc('certificates.get', { id: b.certificate.id })).body.data).toMatchObject({ status: 'expired', renew_due: true })
      const stats = (await w.viewer.rpc('certificate_stats.get')).body.data
      expect(stats).toMatchObject({ active: 1, expiring_within_7_days: 1, expiring_within_30_days: 1, expired: 1, issued_last_7_days: 2, active_cas: 2 })

      const viewerDashboard = (await w.viewer.rpc('dashboard.get')).body.data
      expect(viewerDashboard.stats).toMatchObject({ active: 1, expiring_within_30_days: 1 })
      expect(viewerDashboard.expiry_weeks).toHaveLength(13)
      expect(viewerDashboard.expiry_weeks[0].count).toBe(1)
      expect(viewerDashboard.expiry_weeks.slice(1).every((week: { count: number }) => week.count === 0)).toBe(true)
      expect(viewerDashboard.issued_per_week).toHaveLength(8)
      expect(viewerDashboard.issued_per_week.at(-1)).toBe(2)
      expect(viewerDashboard.attention).toContainEqual(expect.objectContaining({ kind: 'certificate_expiring', id: a.certificate.id, name: 'alpha.example.test' }))
      expect(viewerDashboard.cas).toHaveLength(2)
      expect(viewerDashboard.cas.find((ca: { id: string }) => ca.id === w.issuing.id)).toMatchObject({ active_certificates: 1, expiring_within_30_days: 1 })
      // Viewers read the audit log, so they get the activity, named after its subjects.
      expect(viewerDashboard.activity[0]).toMatchObject({ name: 'certificates.issue', subject_id: b.certificate.id, subject_name: 'bravo-device' })
    })

    it('sets up mutual TLS between openssl s_server and s_client with a server and a client certificate', async () => {
      const w = await world()
      await trust()
      const server = await ok(w.operator, 'certificates.issue', { template_id: w.server.id, keygen: keygen(), sans: [{ type: 'dns', value: 'localhost' }, { type: 'ip', value: '127.0.0.1' }] })
      const client = await ok(w.operator, 'certificates.issue', { template_id: w.client.id, keygen: keygen(), common_name: 'client-1', sans: [{ type: 'uri', value: 'spiffe://example.test/client-1' }] })
      tmp.write('server.pem', server.certificate.pem)
      tmp.write('server.key', server.private_key.pem)
      tmp.write('client.pem', client.certificate.pem)
      tmp.write('client.key', client.private_key.pem)
      expect(tmp.run(['x509', '-in', 'client.pem', '-noout', '-ext', 'extendedKeyUsage'])).toContain('TLS Web Client Authentication')

      const port = await freePort()
      const s = spawn('openssl', ['s_server', '-accept', String(port), '-cert', 'server.pem', '-key', 'server.key', '-cert_chain', 'issuing.pem', '-CAfile', 'cas.pem', '-Verify', '1', '-verify_return_error', '-www'], { cwd: tmp.dir })
      try {
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('s_server did not start')), 10_000)
          s.stdout.on('data', (chunk) => {
            if (String(chunk).includes('ACCEPT')) {
              clearTimeout(timer)
              resolve()
            }
          })
          s.once('exit', (code) => reject(new Error(`s_server exited with ${code}`)))
        })
        const connect = (extra: string[]) =>
          spawnSync(
            'openssl',
            ['s_client', '-connect', `127.0.0.1:${port}`, '-servername', 'localhost', '-verify_hostname', 'localhost', '-CAfile', 'root.pem', '-verify_return_error', '-ign_eof', ...extra],
            { cwd: tmp.dir, input: 'GET / HTTP/1.0\r\n\r\n', encoding: 'utf8', timeout: 15_000 },
          )
        const mutual = connect(['-cert', 'client.pem', '-key', 'client.key', '-cert_chain', 'issuing.pem'])
        expect(mutual.stdout).toContain('Verify return code: 0 (ok)')
        expect(mutual.stdout).toContain('HTTP/1.0 200 ok')

        const anonymous = connect([])
        expect(anonymous.stdout).not.toContain('HTTP/1.0 200 ok')
        expect(`${anonymous.stdout}${anonymous.stderr}`).toMatch(/certificate required|alert|handshake failure/i)
      } finally {
        s.kill()
      }
    })
  })
})
