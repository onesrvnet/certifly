import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Context } from '@certifly/core/context'
import { rewrapCaKeys } from '@certifly/core/ca-keys'
import { rebuildDueCrls } from '@certifly/core/crls'
import { type Database, schema } from '@certifly/db'
import { LocalKeyProvider, loadKeyvaultConfig } from '@certifly/keyvault'
import { setup } from '@nuxt/test-utils/e2e'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, query, resetState, serverOptions, setupAdmin } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('certificate authority tests: the openssl CLI is not installed, so the OpenSSL checks are skipped')

const none = { dns: [], ip: [], email: [] }
const subject = (cn: string) => [
  { type: 'CN', value: cn },
  { type: 'O', value: 'certifly tests' },
]
const rootBody = (slug = 'root') => ({ signing: 'self_signed', name: `Root ${slug}`, slug, subject: subject(`Test Root ${slug}`), validity_days: 3650, path_length: 2 })
const internalBody = (parent_ca_id: string, slug: string, overrides: Record<string, unknown> = {}) => ({
  signing: 'internal',
  parent_ca_id,
  name: `CA ${slug}`,
  slug,
  subject: subject(`Test ${slug}`),
  validity_days: 365,
  path_length: 0,
  name_constraints: { permitted: { ...none, dns: ['example.test'], ip: ['10.0.0.0/8'] }, excluded: none },
  ...overrides,
})
const externalBody = (slug = 'ext-l2') => ({
  signing: 'external',
  name: `External ${slug}`,
  slug,
  subject: subject(`External ${slug}`),
  path_length: 1,
  name_constraints: { permitted: { ...none, dns: ['ext.example.test'] }, excluded: none },
})

/** A scratch directory for OpenSSL, with a runner that fails the test on errors. */
function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-ca-test-'))
  const run = (args: string[]) => {
    const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' })
    if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
    return result.stdout + result.stderr
  }
  const write = (name: string, data: string | Uint8Array) => writeFileSync(join(dir, name), data)
  return { dir, run, write, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

async function download(path: string) {
  const response = await new Client().get(path)
  return { status: response.status, type: response.headers.get('content-type'), cache: response.headers.get('cache-control'), body: new Uint8Array(await response.arrayBuffer()) }
}

/** core run directly against the test database, as the cron worker would. */
async function workerContext(master_key = process.env.CERTIFLY_MASTER_KEY!, previous?: string) {
  const sql = postgres(process.env.DATABASE_URL!, { max: 2, onnotice: () => {} })
  const db = drizzle(sql, { schema, casing: 'snake_case' }) as unknown as Database
  const config = await loadKeyvaultConfig({ master_key, previous_master_keys: previous, session_secret: process.env.SECRET_KEY! })
  const ctx = { db, keys: new LocalKeyProvider(config), pki_base_url: process.env.URL!, emit: () => {}, enqueue: () => {} } as unknown as Context
  return { ctx, close: () => sql.end() }
}

describe('certificate authorities', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  async function create(client: Client, body: object) {
    const res = await client.rpc('certificate_authorities.create', body)
    if (res.status !== 200) throw new Error(`create failed: ${JSON.stringify(res.body)}`)
    return res.body.data
  }

  describe('permissions', () => {
    /** An admin, operator and viewer, an admin API key, a root and a pending externally signed CA. */
    async function world() {
      const admin = await setupAdmin()
      const operator = await addUser(admin, 'op@example.com', 'operator')
      const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
      const key = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
      const root = await create(admin, rootBody())
      const ext = await create(admin, externalBody())
      return { admin, operator, viewer, key, root, ext }
    }
    type World = Awaited<ReturnType<typeof world>>
    const actions: [string, (w: World) => [string, object]][] = [
      ['create a root', () => ['certificate_authorities.create', rootBody('another-root')]],
      ['create an internal CA', (w) => ['certificate_authorities.create', internalBody(w.root.id, 'l2')]],
      ['create an externally signed CA', () => ['certificate_authorities.create', externalBody('ext-2')]],
      ['import a certificate', (w) => ['certificate_authorities.import', { id: w.ext.id, certificate: 'not a certificate', chain: '' }]],
      ['renew', (w) => ['certificate_authorities.renew', { id: w.root.id, validity_days: 100 }]],
      ['disable', (w) => ['certificate_authorities.archive', { id: w.root.id }]],
    ]

    it('lets every role and API keys read', async () => {
      const w = await world()
      for (const client of [w.admin, w.operator, w.viewer]) {
        const list = await client.rpc('certificate_authorities.list')
        expect(list.status).toBe(200)
        expect(list.body.data.map((ca: { slug: string }) => ca.slug).sort()).toEqual(['ext-l2', 'root'])
        expect((await client.rpc('certificate_authorities.get', { id: w.root.id })).status).toBe(200)
      }
      const viaKey = await new Client().rpcWithKey(w.key, 'certificate_authorities.get', { id: w.root.id })
      expect(viaKey.status).toBe(200)
      // A key cannot run lifecycle actions, so it is not offered them.
      expect(viaKey.body.data.permissions).toEqual({ read: true, import: false, renew: false, disable: false, revoke: false })
      const asViewer = await w.viewer.rpc('certificate_authorities.get', { id: w.root.id })
      expect(asViewer.body.data.permissions).toEqual({ read: true, import: false, renew: false, disable: false, revoke: false })
      const asAdmin = await w.admin.rpc('certificate_authorities.get', { id: w.root.id })
      expect(asAdmin.body.data.permissions).toEqual({ read: true, import: false, renew: true, disable: true, revoke: false })
      expect((await w.viewer.rpc('certificate_authorities.get', { id: crypto.randomUUID() })).status).toBe(404)
    })

    it('refuses viewers and operators', async () => {
      const w = await world()
      for (const [who, client] of [['viewer', w.viewer], ['operator', w.operator]] as const) {
        for (const [label, action] of actions) {
          const [method, body] = action(w)
          const { status, body: answer } = await client.rpc(method, body)
          expect({ who, label, status, code: answer.error?.code }).toEqual({ who, label, status: 403, code: 'forbidden' })
        }
      }
    })

    it('refuses API keys, even an admin’s right after signing in', async () => {
      const w = await world()
      for (const [label, action] of actions) {
        const [method, body] = action(w)
        const { status } = await new Client().rpcWithKey(w.key, method, body)
        expect({ label, status }).toEqual({ label, status: 403 })
      }
    })

    it('asks an admin whose session has not confirmed it lately to do so, and changes nothing', async () => {
      const w = await world()
      await ageSessions(11)
      for (const [label, action] of actions) {
        const [method, body] = action(w)
        const { status, body: answer } = await w.admin.rpc(method, body)
        expect({ label, status, code: answer.error?.code }).toEqual({ label, status: 403, code: 'reauth_required' })
      }
      const list = (await w.admin.rpc('certificate_authorities.list')).body.data
      expect(list.map((ca: { slug: string; status: string }) => [ca.slug, ca.status]).sort()).toEqual([
        ['ext-l2', 'pending_certificate'],
        ['root', 'active'],
      ])
    })

    it('lets an admin with a fresh session run each action', async () => {
      const w = await world()
      for (const [label, action] of actions) {
        const [method, body] = action(w)
        const { status, body: answer } = await w.admin.rpc(method, body)
        // The import body is no certificate: it gets past the permission checks and is refused for what it is.
        const expected = label === 'import a certificate' ? { status: 400, code: 'invalid_certificate' } : { status: 200, code: undefined }
        expect({ label, status, code: answer.error?.code }).toEqual({ label, ...expected })
      }
      const events = (await w.admin.rpc('events.list', { subject_type: 'certificate_authority' })).body.data.map((e: { name: string }) => e.name)
      expect(events).toEqual(expect.arrayContaining(['certificate_authorities.create', 'certificate_authorities.renew', 'certificate_authorities.disable']))
      // Audit data holds ids and facts only, never key material.
      const [{ dump }] = await query()`select coalesce(string_agg(data::text, ' '), '') as dump from events where subject_type = 'certificate_authority'`
      expect(dump).not.toMatch(/PRIVATE KEY|ciphertext|wrapped_dek/)
    })
  })

  describe('validation', () => {
    it('requires name constraints below a root, inside the parent’s, and pathLen and validity that fit', async () => {
      const admin = await setupAdmin()
      const root = await create(admin, { ...rootBody(), path_length: 1 })
      const l2 = await create(admin, internalBody(root.id, 'l2', { path_length: 0 }))
      const code = async (body: object) => (await admin.rpc('certificate_authorities.create', body)).body.error?.code

      expect(await code(internalBody(root.id, 'x1', { name_constraints: null }))).toBe('name_constraints_required')
      expect(await code({ ...externalBody('x2'), name_constraints: { permitted: none, excluded: { ...none, dns: ['bad.test'] } } })).toBe('name_constraints_required')
      expect(await code(internalBody(l2.id, 'x3'))).toBe('path_length_exceeded')
      expect(await code(internalBody(root.id, 'x4', { path_length: 1 }))).toBe('path_length_exceeded')
      expect(await code(internalBody(root.id, 'x5', { validity_days: 5000 }))).toBe('validity_not_nested')
      expect(await code({ ...rootBody(), slug: 'Root CA' })).toBe('invalid_slug')
      expect(await code(rootBody())).toBe('slug_taken')
      expect(await code({ ...rootBody('nocn'), subject: [{ type: 'O', value: 'x' }] })).toBe('invalid_dn')

      const constrained = await create(admin, { ...rootBody('constrained'), name_constraints: { permitted: { ...none, dns: ['corp.test'] }, excluded: none } })
      expect(await code(internalBody(constrained.id, 'x6', { name_constraints: { permitted: { ...none, dns: ['other.test'] }, excluded: none } }))).toBe('name_constraints_not_subset')
      expect((await admin.rpc('certificate_authorities.create', internalBody(constrained.id, 'x7', { name_constraints: { permitted: { ...none, dns: ['a.corp.test'] }, excluded: none } }))).status).toBe(200)
    })
  })

  describe.skipIf(!hasOpenssl)('with OpenSSL', () => {
    const tmp = scratch()
    afterAll(() => tmp.cleanup())

    it('builds root → L2 → L3 whose public certificates and chain pass openssl verify', async () => {
      const admin = await setupAdmin()
      const root = await create(admin, rootBody())
      const l2 = await create(admin, internalBody(root.id, 'l2', { path_length: 1 }))
      const l3 = await create(admin, internalBody(l2.id, 'l3', { name_constraints: { permitted: { ...none, dns: ['svc.example.test'], ip: ['10.1.0.0/16'] }, excluded: none } }))
      const l3Key = l3.versions[0].key_id
      const l2Key = l2.versions[0].key_id
      expect(l3.urls).toEqual({
        crl: `${process.env.URL}/api/pki/crl/l3.crl`,
        certificate: `${process.env.URL}/api/pki/ca/l3.crt`,
        chain: `${process.env.URL}/api/pki/ca/l3/chain.pem`,
        key_crl: `${process.env.URL}/api/pki/crl/l3/${l3Key}.crl`,
        key_certificate: `${process.env.URL}/api/pki/ca/l3/${l3Key}.crt`,
      })
      // Certificates name the key that signed them, so the URLs stay right after a new-key renewal.
      expect(l3.active_certificate.crl_urls).toEqual([`${process.env.URL}/api/pki/crl/l2/${l2Key}.crl`])
      expect(l3.active_certificate.ca_issuer_urls).toEqual([`${process.env.URL}/api/pki/ca/l2/${l2Key}.crt`])
      expect(l3.parent).toMatchObject({ id: l2.id, slug: 'l2' })
      expect(l3.chain.map((c: { subject: string }) => c.subject)).toEqual([l2.subject_dn, root.subject_dn])

      const rootCrt = await download('/api/pki/ca/root.crt')
      expect(rootCrt).toMatchObject({ status: 200, type: 'application/pkix-cert' })
      expect(rootCrt.cache).toMatch(/^public, max-age=\d+/)
      tmp.write('root.der', rootCrt.body)
      tmp.run(['x509', '-inform', 'DER', '-in', 'root.der', '-out', 'root.pem'])
      const chain = await download('/api/pki/ca/l3/chain.pem')
      expect(chain).toMatchObject({ status: 200, type: 'application/pem-certificate-chain' })
      const pem = new TextDecoder().decode(chain.body)
      expect(pem.match(/BEGIN CERTIFICATE/g)).toHaveLength(3)
      const [l3Pem, l2Pem] = pem.split(/(?<=-----END CERTIFICATE-----\n)/)
      tmp.write('l3.pem', l3Pem!)
      tmp.write('l2.pem', l2Pem!)
      expect(tmp.run(['verify', '-CAfile', 'root.pem', '-untrusted', 'l2.pem', 'l3.pem'])).toContain('l3.pem: OK')
      expect(tmp.run(['x509', '-in', 'l3.pem', '-noout', '-text'])).toMatch(/X509v3 Name Constraints: critical\s+Permitted:\s+DNS:svc\.example\.test/)

      expect((await download('/api/pki/ca/nope.crt')).status).toBe(404)
      expect((await download('/api/pki/crl/root.crt')).status).toBe(404)
    })

    it('imports an externally signed CA, refuses wrong certificates with a clear code, and keeps versions', async () => {
      const admin = await setupAdmin()
      tmp.run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-384', '-noenc', '-keyout', 'ext-root.key', '-out', 'ext-root.pem', '-days', '3650', '-subj', '/CN=OpenSSL Test Root', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
      const rootPem = tmp.run(['x509', '-in', 'ext-root.pem'])
      const extensions = (nc: boolean) =>
        `[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\n${nc ? 'nameConstraints=critical,permitted;DNS:ext.example.test\n' : ''}subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n`
      const sign = (csr: string, name: string, nc = true) => {
        tmp.write(`${name}.csr`, csr)
        tmp.write(`${name}.ext`, extensions(nc))
        tmp.run(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ext-root.pem', '-CAkey', 'ext-root.key', '-set_serial', `0x${Math.floor(Math.random() * 1e12).toString(16)}`, '-days', '1825', '-extfile', `${name}.ext`, '-extensions', 'v3_ca', '-out', `${name}.pem`])
        return tmp.run(['x509', '-in', `${name}.pem`])
      }

      const ext = await create(admin, externalBody())
      expect(ext).toMatchObject({ status: 'pending_certificate', active_certificate: null, permissions: { import: true } })
      expect(ext.pending_csr.pem).toContain('BEGIN CERTIFICATE REQUEST')
      expect((await download('/api/pki/ca/ext-l2.crt')).status).toBe(404)
      tmp.write('ext.csr.pem', ext.pending_csr.pem)
      expect(tmp.run(['req', '-in', 'ext.csr.pem', '-noout', '-verify', '-text'])).toMatch(/X509v3 Name Constraints: critical/)

      // A certificate for someone else's key.
      tmp.run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'other.key', '-out', 'other.csr', '-subj', '/CN=External ext-l2/O=certifly tests'])
      const other = sign(tmp.run(['req', '-in', 'other.csr']), 'other')
      const wrongKey = await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: other, chain: rootPem })
      expect(wrongKey.status).toBe(400)
      expect(wrongKey.body.error.code).toBe('public_key_mismatch')
      expect(wrongKey.body.error.details.errors).toEqual([expect.objectContaining({ code: 'public_key_mismatch' })])

      const withoutConstraints = await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: sign(ext.pending_csr.pem, 'nonc', false), chain: rootPem })
      expect(withoutConstraints.body.error).toMatchObject({ code: 'name_constraints_missing' })
      const good = sign(ext.pending_csr.pem, 'ext-l2')
      const noChain = await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: good, chain: '' })
      expect(noChain.body.error).toMatchObject({ code: 'chain_incomplete' })

      const imported = await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: good, chain: rootPem })
      expect(imported.status).toBe(200)
      expect(imported.body.data).toMatchObject({ status: 'active', pending_csr: null, chain_subjects: ['CN=OpenSSL Test Root'], crl: { crl_number: '1' } })
      expect(imported.body.data.versions).toHaveLength(1)
      expect((await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: good, chain: rootPem })).body.error.code).toBe('certificate_already_installed')

      // The root operator renews it: same CSR, new certificate, a second version; the first stays.
      const again = await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: sign(ext.pending_csr.pem, 'ext-l2-v2'), chain: rootPem })
      expect(again.status).toBe(200)
      expect(again.body.data.versions.map((v: { version: number; active: boolean }) => [v.version, v.active])).toEqual([
        [2, true],
        [1, false],
      ])
      expect(again.body.data.crl.crl_number).toBe('2')

      // An internal L3 under the imported L2 verifies against the outside root.
      const l3 = await create(admin, internalBody(ext.id, 'ext-l3', { name_constraints: { permitted: { ...none, dns: ['svc.ext.example.test'] }, excluded: none } }))
      expect(l3.chain.map((c: { subject: string }) => c.subject)).toEqual([ext.subject_dn, 'CN=OpenSSL Test Root'])
      const chain = new TextDecoder().decode((await download('/api/pki/ca/ext-l3/chain.pem')).body)
      tmp.write('ext-chain.pem', chain)
      tmp.write('ext-l3.pem', l3.active_certificate.pem)
      expect(tmp.run(['verify', '-CAfile', 'ext-root.pem', '-untrusted', 'ext-chain.pem', 'ext-l3.pem'])).toContain('ext-l3.pem: OK')

      // Renewing an externally signed CA means a new key and a new CSR, waiting for its import.
      const renewed = await admin.rpc('certificate_authorities.renew', { id: ext.id })
      expect(renewed.status).toBe(200)
      expect(renewed.body.data.status).toBe('active')
      expect(renewed.body.data.pending_csr.key_id).not.toBe(ext.pending_csr.key_id)
      const rotated = await admin.rpc('certificate_authorities.import', { id: ext.id, certificate: sign(renewed.body.data.pending_csr.pem, 'ext-l2-v3'), chain: rootPem })
      expect(rotated.status).toBe(200)
      expect(rotated.body.data.versions[0]).toMatchObject({ version: 3, active: true, key_id: renewed.body.data.pending_csr.key_id })

      const importIntoRoot = await admin.rpc('certificate_authorities.import', { id: l3.id, certificate: good, chain: rootPem })
      expect(importIntoRoot.body.error.code).toBe('not_externally_signed')
    })

    it('publishes CRLs that OpenSSL reads, with a number that grows on every rebuild', async () => {
      const admin = await setupAdmin()
      const root = await create(admin, rootBody())
      const l2 = await create(admin, internalBody(root.id, 'l2'))
      tmp.write('crl-root.pem', root.active_certificate.pem)

      const crlNumber = async () => {
        const crl = await download('/api/pki/crl/root.crl')
        expect(crl).toMatchObject({ status: 200, type: 'application/pkix-crl' })
        tmp.write('root.crl', crl.body)
        const out = tmp.run(['crl', '-inform', 'DER', '-in', 'root.crl', '-CAfile', 'crl-root.pem', '-noout', '-text'])
        expect(out).toMatch(/verify OK/)
        return { number: Number(out.match(/X509v3 CRL Number:\s+(\d+)/)![1]), text: out }
      }
      expect((await crlNumber()).number).toBe(1)

      const renewed = await admin.rpc('certificate_authorities.renew', { id: root.id, validity_days: 3000 })
      expect(renewed.status).toBe(200)
      expect(renewed.body.data.versions).toHaveLength(2)
      tmp.write('crl-root.pem', renewed.body.data.active_certificate.pem)
      expect((await crlNumber()).number).toBe(2)

      // The scheduled job rebuilds a CRL once it is inside its overlap window, and lists revoked child CAs.
      const worker = await workerContext()
      try {
        expect(await rebuildDueCrls(worker.ctx)).toEqual({ rebuilt: 0, expired: 0 })
        await query()`update ca_certificates set revoked_at = now() - interval '1 minute', revocation_reason = 1 where ca_id = ${l2.id}`
        await query()`update crls set next_update = now() + interval '1 hour' where ca_id = ${root.id}`
        expect(await rebuildDueCrls(worker.ctx)).toEqual({ rebuilt: 1, expired: 0 })
      } finally {
        await worker.close()
      }
      const third = await crlNumber()
      expect(third.number).toBe(3)
      expect(third.text.toLowerCase()).toContain(`serial number: ${l2.active_certificate.serial}`)
      expect(third.text).toMatch(/Key Compromise/)
    })

    it('keeps serving public material after a CA is disabled, and stops it signing', async () => {
      const admin = await setupAdmin()
      const root = await create(admin, rootBody())
      const disabled = await admin.rpc('certificate_authorities.archive', { id: root.id })
      expect(disabled.body.data).toMatchObject({ status: 'disabled', permissions: { renew: false, disable: false } })
      expect(disabled.body.data.disabled_at).not.toBeNull()
      expect((await admin.rpc('certificate_authorities.archive', { id: root.id })).status).toBe(200)

      expect((await download('/api/pki/ca/root.crt')).status).toBe(200)
      expect((await download('/api/pki/ca/root/chain.pem')).status).toBe(200)
      const crl = await download('/api/pki/crl/root.crl')
      expect(crl.status).toBe(200)
      tmp.write('disabled.crl', crl.body)
      expect(tmp.run(['crl', '-inform', 'DER', '-in', 'disabled.crl', '-noout', '-text'])).toMatch(/CRL Number:\s+1/)

      expect((await admin.rpc('certificate_authorities.create', internalBody(root.id, 'l2'))).body.error.code).toBe('parent_not_active')
      expect((await admin.rpc('certificate_authorities.renew', { id: root.id, validity_days: 10 })).body.error.code).toBe('ca_disabled')
      const [{ n }] = await query()`select count(*)::int as n from events where name = 'certificate_authorities.disable'`
      expect(n).toBe(1)
    })

    it('rewraps CA keys under a new master key, after which they still sign', async () => {
      const admin = await setupAdmin()
      const root = await create(admin, rootBody())
      const current = process.env.CERTIFLY_MASTER_KEY!
      const next = 'b2'.repeat(32)
      const worker = await workerContext(next, current)
      try {
        const [before] = await query()`select kek_id from ca_keys`
        expect(await rewrapCaKeys(worker.ctx)).toEqual({ rewrapped: 1 })
        expect(await rewrapCaKeys(worker.ctx)).toEqual({ rewrapped: 0 })
        const [after] = await query()`select kek_id from ca_keys`
        expect(after!.kek_id).not.toBe(before!.kek_id)
        // Signing a CRL with the rewrapped key works under the new master key alone.
        const fresh = await workerContext(next)
        try {
          await query()`update crls set next_update = now() + interval '1 hour' where ca_id = ${root.id}`
          expect(await rebuildDueCrls(fresh.ctx)).toEqual({ rebuilt: 1, expired: 0 })
        } finally {
          await fresh.close()
        }
      } finally {
        await worker.close()
      }
    })
  })
})
