import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, query, resetState, serverOptions, setupAdmin, waitFor } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('revocation tests: the openssl CLI is not installed, so the OpenSSL checks are skipped')

const none = { dns: [], ip: [], email: [] }
const DAY = 86400

/** A scratch directory for OpenSSL. `run` fails the test on errors; `status` reports them. */
function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-revoke-test-'))
  const status = (args: string[]) => {
    const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' })
    return { code: result.status, out: result.stdout + result.stderr }
  }
  const run = (args: string[]) => {
    const result = status(args)
    if (result.code !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.out}`)
    return result.out
  }
  const write = (name: string, data: string | Uint8Array) => writeFileSync(join(dir, name), data)
  return { dir, run, status, write, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

async function ok(client: Client, method: string, body: object) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

async function download(path: string) {
  const response = await new Client().get(path)
  if (response.status !== 200) throw new Error(`GET ${path}: ${response.status}`)
  return new Uint8Array(await response.arrayBuffer())
}

/** The path of an absolute URL embedded in a certificate, to fetch it from the test server. */
const pathOf = (url: string) => new URL(url).pathname

/** The highest CRL number of one key of a CA, or 0. */
async function crlNumber(ca_id: string, key_id: string): Promise<number> {
  const [row] = await query()`select crl_number::int as n from crls where ca_id = ${ca_id} and key_id = ${key_id}`
  return row?.n ?? 0
}

/** Waits until the background job has published a newer CRL for a key. */
const newerCrl = (ca_id: string, key_id: string, than: number) => waitFor(async () => (await crlNumber(ca_id, key_id)) > than, 'the CRL rebuild')

const keygen = { algorithm: 'ecdsa-p256', format: 'pem' }

/** A root, an issuing CA below it, a server template, and an admin, operator (with an API key) and viewer. */
async function world() {
  const admin = await setupAdmin()
  const operator = await addUser(admin, 'op@example.com', 'operator')
  const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
  const operatorKey = (await operator.rpc('api_keys.create', { name: 'automation' })).body.data.secret as string
  const adminKey = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
  const root = await ok(admin, 'certificate_authorities.create', {
    signing: 'self_signed',
    name: 'Root',
    slug: 'root',
    subject: [{ type: 'CN', value: 'Revocation Root' }],
    validity_days: 3650,
    path_length: 1,
  })
  const issuing = await ok(admin, 'certificate_authorities.create', {
    signing: 'internal',
    parent_ca_id: root.id,
    name: 'Issuing',
    slug: 'issuing',
    subject: [{ type: 'CN', value: 'Revocation Issuing CA' }],
    validity_days: 365,
    path_length: 0,
    name_constraints: { permitted: { ...none, dns: ['example.test'] }, excluded: none },
  })
  const web = await ok(admin, 'templates.create', {
    preset: 'webserver_tls',
    name: 'Web',
    slug: 'web',
    ca_id: issuing.id,
    allowed_dns: ['**.example.test'],
    max_ttl_seconds: 90 * DAY,
    default_ttl_seconds: 30 * DAY,
  })
  const issue = async (name: string) =>
    (await ok(operator, 'certificates.issue', { template_id: web.id, keygen, sans: [{ type: 'dns', value: name }] })).certificate as {
      id: string
      serial: string
      pem: string
      details: { crl_urls: string[]; ca_issuer_urls: string[] }
    }
  return { admin, operator, viewer, operatorKey, adminKey, root, issuing, web, issue }
}

describe('revocation', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  describe('leaf certificates', () => {
    it('lets operators revoke, also with an API key, and refuses viewers', async () => {
      const w = await world()
      const first = await w.issue('one.example.test')
      const second = await w.issue('two.example.test')

      const asViewer = await w.viewer.rpc('certificates.revoke', { id: first.id, reason: 'key_compromise' })
      expect(asViewer).toMatchObject({ status: 403, body: { error: { code: 'forbidden' } } })
      expect((await w.operator.rpc('certificates.revoke', { id: first.id, reason: 'certificate_hold' })).status).toBe(400)

      const revoked = await w.operator.rpc('certificates.revoke', { id: first.id, reason: 'key_compromise' })
      expect(revoked.status).toBe(200)
      expect(revoked.body.data).toMatchObject({ status: 'revoked', revocation_reason: 'key_compromise', permissions: { revoke: false, renew: false } })
      expect(revoked.body.data.revoked_at).not.toBeNull()

      // Revoking again changes nothing, not even the reason or the time.
      const again = await w.operator.rpc('certificates.revoke', { id: first.id, reason: 'superseded' })
      expect(again.body.data).toMatchObject({ revocation_reason: 'key_compromise', revoked_at: revoked.body.data.revoked_at })

      const viaKey = await new Client().rpcWithKey(w.operatorKey, 'certificates.revoke', { id: second.id, reason: 'cessation_of_operation' })
      expect(viaKey.status).toBe(200)
      expect((await w.operator.rpc('certificates.revoke', { id: crypto.randomUUID(), reason: 'unspecified' })).status).toBe(404)

      const events = await query()`select actor_type, data from events where name = 'certificates.revoke' order by created_at`
      expect(events.map((e) => [e.actor_type, e.data.reason])).toEqual([
        ['user', 'key_compromise'],
        ['api_key', 'cessation_of_operation'],
      ])
      // Revoked certificates cannot be renewed.
      expect((await w.operator.rpc('certificates.renew', { id: first.id, keygen })).body.error.code).toBe('certificate_not_renewable')
      const stats = (await w.viewer.rpc('certificate_stats.get')).body.data
      expect(stats.revoked).toBe(2)
    })
  })

  describe('certificate authorities', () => {
    it('lets only an admin with a fresh session revoke a CA, and refuses roots', async () => {
      const w = await world()
      const body = { id: w.issuing.id, reason: 'key_compromise' }
      expect((await w.operator.rpc('certificate_authorities.revoke', body)).status).toBe(403)
      expect((await w.viewer.rpc('certificate_authorities.revoke', body)).status).toBe(403)
      expect((await new Client().rpcWithKey(w.adminKey, 'certificate_authorities.revoke', body)).status).toBe(403)
      expect((await w.admin.rpc('certificate_authorities.revoke', { id: w.root.id, reason: 'key_compromise' })).body.error.code).toBe('ca_not_revocable')

      await ageSessions(30)
      const stale = await w.admin.rpc('certificate_authorities.revoke', body)
      expect(stale).toMatchObject({ status: 403, body: { error: { code: 'reauth_required' } } })
      const [{ revoked }] = await query()`select count(*)::int as revoked from ca_certificates where revoked_at is not null`
      expect(revoked).toBe(0)
    })
  })

  describe.skipIf(!hasOpenssl)('with OpenSSL', () => {
    const tmp = scratch()
    afterAll(() => tmp.cleanup())

    it('lists a revoked leaf on the CRL its CDP names, so openssl -crl_check rejects it and accepts the others', async () => {
      const w = await world()
      const revoked = await w.issue('revoked.example.test')
      const kept = await w.issue('kept.example.test')
      const key = w.issuing.versions[0].key_id
      const before = await crlNumber(w.issuing.id, key)

      expect((await w.operator.rpc('certificates.revoke', { id: revoked.id, reason: 'key_compromise' })).status).toBe(200)
      await newerCrl(w.issuing.id, key, before)

      expect(revoked.details.crl_urls).toEqual([`${process.env.URL}/api/pki/crl/issuing/${key}.crl`])
      tmp.write('leaf.crl', await download(pathOf(revoked.details.crl_urls[0]!)))
      tmp.run(['crl', '-inform', 'DER', '-in', 'leaf.crl', '-out', 'leaf-crl.pem'])
      tmp.write('root.pem', w.root.active_certificate.pem)
      tmp.write('issuing.pem', w.issuing.active_certificate.pem)
      tmp.write('revoked.pem', revoked.pem)
      tmp.write('kept.pem', kept.pem)
      const text = tmp.run(['crl', '-in', 'leaf-crl.pem', '-CAfile', 'issuing.pem', '-noout', '-text'])
      expect(text).toMatch(/verify OK/)
      expect(text).toMatch(/Key Compromise/)

      const verify = (file: string) => tmp.status(['verify', '-crl_check', '-CAfile', 'root.pem', '-untrusted', 'issuing.pem', '-CRLfile', 'leaf-crl.pem', file])
      const rejected = verify('revoked.pem')
      expect(rejected.code).not.toBe(0)
      expect(rejected.out).toMatch(/certificate revoked/)
      expect(verify('kept.pem')).toMatchObject({ code: 0 })
      // The CA's plain CRL URL serves the same key's CRL while that key is current.
      expect(Buffer.from(await download('/api/pki/crl/issuing.crl')).equals(Buffer.from(await download(pathOf(revoked.details.crl_urls[0]!))))).toBe(true)
    })

    it('puts a revoked child CA on its parent’s CRL and disables it', async () => {
      const w = await world()
      const rootKey = w.root.versions[0].key_id
      const before = await crlNumber(w.root.id, rootKey)
      const res = await w.admin.rpc('certificate_authorities.revoke', { id: w.issuing.id, reason: 'ca_compromise' })
      expect(res.status).toBe(200)
      expect(res.body.data).toMatchObject({ status: 'disabled', revocation_reason: 'ca_compromise', permissions: { revoke: false, renew: false } })
      expect(res.body.data.revoked_at).not.toBeNull()
      // Revoking again changes nothing.
      expect((await w.admin.rpc('certificate_authorities.revoke', { id: w.issuing.id, reason: 'superseded' })).body.data.revocation_reason).toBe('ca_compromise')
      await newerCrl(w.root.id, rootKey, before)

      tmp.write('root.pem', w.root.active_certificate.pem)
      tmp.write('root.crl', await download(pathOf(w.issuing.active_certificate.crl_urls[0])))
      const text = tmp.run(['crl', '-inform', 'DER', '-in', 'root.crl', '-CAfile', 'root.pem', '-noout', '-text'])
      expect(text).toMatch(/verify OK/)
      expect(text.toLowerCase()).toContain(`serial number: ${w.issuing.active_certificate.serial}`)
      expect(text).toMatch(/CA Compromise/)
      tmp.write('issuing.pem', w.issuing.active_certificate.pem)
      tmp.write('root-crl.pem', tmp.run(['crl', '-inform', 'DER', '-in', 'root.crl']))
      const rejected = tmp.status(['verify', '-crl_check', '-CAfile', 'root.pem', '-CRLfile', 'root-crl.pem', 'issuing.pem'])
      expect(rejected.out).toMatch(/certificate revoked/)
      // Disabled means it signs nothing more.
      expect((await w.operator.rpc('certificates.issue', { template_id: w.web.id, keygen, sans: [{ type: 'dns', value: 'late.example.test' }] })).body.error.code).toBe('ca_disabled')
      const [event] = await query()`select data from events where name = 'certificate_authorities.revoke'`
      expect(event!.data).toMatchObject({ reason: 'ca_compromise', parent_ca_id: w.root.id })
    })

    it('keeps one CRL per key after a new-key renewal of an externally signed CA, so old certificates stay checkable', async () => {
      const admin = await setupAdmin()
      const operator = await addUser(admin, 'op@example.com', 'operator')
      tmp.run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-384', '-noenc', '-keyout', 'ext-root.key', '-out', 'ext-root.pem', '-days', '3650', '-subj', '/CN=Outside Root', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
      const rootPem = tmp.run(['x509', '-in', 'ext-root.pem'])
      tmp.write('ext.ext', '[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\nnameConstraints=critical,permitted;DNS:ext.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
      const sign = (csr: string, name: string, validity: string[] = ['-days', '1825']) => {
        tmp.write(`${name}.csr`, csr)
        tmp.run(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ext-root.pem', '-CAkey', 'ext-root.key', '-set_serial', `0x${Math.floor(Math.random() * 1e12).toString(16)}`, ...validity, '-extfile', 'ext.ext', '-extensions', 'v3_ca', '-out', `${name}.pem`])
        return tmp.run(['x509', '-in', `${name}.pem`])
      }

      const ext = await ok(admin, 'certificate_authorities.create', {
        signing: 'external',
        name: 'Outside L2',
        slug: 'outside',
        subject: [{ type: 'CN', value: 'Outside L2' }],
        path_length: 0,
        name_constraints: { permitted: { ...none, dns: ['ext.example.test'] }, excluded: none },
      })
      const v1 = await ok(admin, 'certificate_authorities.import', { id: ext.id, certificate: sign(ext.pending_csr.pem, 'v1'), chain: rootPem })
      const oldKey = v1.versions[0].key_id
      const template = await ok(admin, 'templates.create', { preset: 'webserver_tls', name: 'Ext', slug: 'ext', ca_id: ext.id, allowed_dns: ['**.ext.example.test'] })
      const issue = async (name: string) =>
        (await ok(operator, 'certificates.issue', { template_id: template.id, keygen, sans: [{ type: 'dns', value: name }] })).certificate
      const oldRevoked = await issue('a.ext.example.test')
      const oldKept = await issue('b.ext.example.test')

      // The root operator signs a CSR for a new key; the CA moves to it.
      const renewed = await ok(admin, 'certificate_authorities.renew', { id: ext.id })
      const newKey = renewed.pending_csr.key_id
      expect(newKey).not.toBe(oldKey)
      const newCsr = renewed.pending_csr.pem
      const v2 = await ok(admin, 'certificate_authorities.import', { id: ext.id, certificate: sign(newCsr, 'v2'), chain: rootPem })
      expect(v2.versions[0]).toMatchObject({ version: 2, key_id: newKey, active: true })
      expect(v2.crls.map((crl: { key_id: string; active: boolean }) => [crl.key_id, crl.active])).toEqual([
        [newKey, true],
        [oldKey, false],
      ])

      // A certificate older than the newest version cannot come in as the newest version.
      const older = await admin.rpc('certificate_authorities.import', {
        id: ext.id,
        certificate: sign(newCsr, 'stale', ['-not_before', '20260101000000Z', '-not_after', '20300101000000Z']),
        chain: rootPem,
      })
      expect(older).toMatchObject({ status: 409, body: { error: { code: 'certificate_older_than_current', details: { current_version: 2 } } } })

      const fresh = await issue('c.ext.example.test')
      expect(fresh.details.crl_urls).toEqual([`${process.env.URL}/api/pki/crl/outside/${newKey}.crl`])
      expect(oldRevoked.details.crl_urls).toEqual([`${process.env.URL}/api/pki/crl/outside/${oldKey}.crl`])

      const before = await crlNumber(ext.id, oldKey)
      expect((await operator.rpc('certificates.revoke', { id: oldRevoked.id, reason: 'key_compromise' })).status).toBe(200)
      await newerCrl(ext.id, oldKey, before)

      // The old key's certificate comes from the key-specific AIA URL, its CRL from the key-specific CDP.
      tmp.write('old-ca.der', await download(pathOf(oldRevoked.details.ca_issuer_urls[0])))
      tmp.run(['x509', '-inform', 'DER', '-in', 'old-ca.der', '-out', 'old-ca.pem'])
      tmp.write('old.crl', await download(pathOf(oldRevoked.details.crl_urls[0])))
      tmp.run(['crl', '-inform', 'DER', '-in', 'old.crl', '-out', 'old-crl.pem'])
      expect(tmp.run(['crl', '-in', 'old-crl.pem', '-CAfile', 'old-ca.pem', '-noout'])).toMatch(/verify OK/)
      tmp.write('old-revoked.pem', oldRevoked.pem)
      tmp.write('old-kept.pem', oldKept.pem)
      const verifyOld = (file: string) => tmp.status(['verify', '-crl_check', '-CAfile', 'ext-root.pem', '-untrusted', 'old-ca.pem', '-CRLfile', 'old-crl.pem', file])
      expect(verifyOld('old-kept.pem')).toMatchObject({ code: 0 })
      const rejected = verifyOld('old-revoked.pem')
      expect(rejected.code).not.toBe(0)
      expect(rejected.out).toMatch(/certificate revoked/)

      // The new key's CRL is signed by the new key and serves the certificates it signs.
      tmp.write('new-ca.pem', v2.active_certificate.pem)
      tmp.write('new.crl', await download(pathOf(fresh.details.crl_urls[0])))
      tmp.run(['crl', '-inform', 'DER', '-in', 'new.crl', '-out', 'new-crl.pem'])
      tmp.write('fresh.pem', fresh.pem)
      expect(tmp.status(['verify', '-crl_check', '-CAfile', 'ext-root.pem', '-untrusted', 'new-ca.pem', '-CRLfile', 'new-crl.pem', 'fresh.pem'])).toMatchObject({ code: 0 })
      expect(Buffer.from(await download('/api/pki/crl/outside.crl')).equals(Buffer.from(await download(pathOf(fresh.details.crl_urls[0]))))).toBe(true)

      // An externally signed CA can only be marked compromised here.
      const marked = await admin.rpc('certificate_authorities.revoke', { id: ext.id, reason: 'key_compromise' })
      expect(marked.body.data).toMatchObject({ status: 'disabled', revocation_reason: 'key_compromise' })
      const [event] = await query()`select data from events where name = 'certificate_authorities.mark_compromised'`
      expect(event!.data).toMatchObject({ reason: 'key_compromise' })
    })
  })
})
