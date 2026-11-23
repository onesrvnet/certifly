import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, Client, query, resetState, serverOptions, setupAdmin } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('inventory tests: the openssl CLI is not installed, so they are skipped')

describe.skipIf(!hasOpenssl)('certificate inventory', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  const dir = mkdtempSync(join(tmpdir(), 'certifly-inventory-test-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))
  const openssl = (args: string[]) => {
    const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' })
    if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
  }

  /** A full-chain file as a server elsewhere would have it: a leaf issued by an outside CA, then that CA. */
  function fullChain() {
    openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '365', '-subj', '/CN=Elsewhere CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=legacy.example.org'])
    writeFileSync(join(dir, 'leaf.ext'), 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:legacy.example.org\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n')
    openssl(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', '0x1234', '-days', '20', '-extfile', 'leaf.ext', '-out', 'leaf.pem'])
    return readFileSync(join(dir, 'leaf.pem'), 'utf8') + readFileSync(join(dir, 'ca.pem'), 'utf8')
  }

  it('imports a leaf once by fingerprint, skips the CA, and refuses to revoke or renew it', async () => {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const operatorKey = (await operator.rpc('api_keys.create', { name: 'scanner' })).body.data.secret as string
    const pem = fullChain()

    expect((await viewer.rpc('certificates.import', { pem })).status).toBe(403)
    expect((await operator.rpc('certificates.import', { pem: 'not a certificate' })).body.error.code).toBe('invalid_pem')
    expect((await operator.rpc('certificates.import', { pem: `${pem}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n` })).body.error.code).toBe('invalid_pem')

    const first = await operator.rpc('certificates.import', { pem, notes: 'old load balancer' })
    expect(first.status).toBe(200)
    expect(first.body.data.imported).toHaveLength(1)
    expect(first.body.data.imported[0]).toMatchObject({ common_name: 'legacy.example.org', issuer_dn: 'CN=Elsewhere CA', serial: '1234' })
    expect(first.body.data.skipped).toEqual([expect.objectContaining({ reason: 'ca_certificate', subject: 'CN=Elsewhere CA' })])
    const id = first.body.data.imported[0].id

    const again = await new Client().rpcWithKey(operatorKey, 'certificates.import', { pem })
    expect(again.status).toBe(200)
    expect(again.body.data.imported).toEqual([])
    expect(again.body.data.skipped).toContainEqual(expect.objectContaining({ reason: 'duplicate', certificate_id: id }))
    const [{ n }] = await query()`select count(*)::int as n from certificates where source = 'import'`
    expect(n).toBe(1)
    const [row] = await query()`select ca_id, ca_cert_id, template_id, issuer_dn, notes from certificates where id = ${id}`
    expect(row).toEqual({ ca_id: null, ca_cert_id: null, template_id: null, issuer_dn: 'CN=Elsewhere CA', notes: 'old load balancer' })

    const listed = await viewer.rpc('certificates.list', { imported: true })
    expect(listed.body.data.map((c: { id: string }) => c.id)).toEqual([id])
    expect(listed.body.data[0]).toMatchObject({ source: 'import', ca: null, template: null, permissions: { renew: false, revoke: false } })
    expect((await viewer.rpc('certificates.list', { imported: false })).body.data).toEqual([])
    const detail = await operator.rpc('certificates.get', { id })
    expect(detail.body.data).toMatchObject({ chain_pem: '', sans: [{ type: 'dns', value: 'legacy.example.org' }], extended_key_usages: ['server_auth'] })

    expect(await operator.rpc('certificates.revoke', { id, reason: 'key_compromise' })).toMatchObject({ status: 409, body: { error: { code: 'certificate_not_revocable' } } })
    expect(await operator.rpc('certificates.renew', { id, keygen: { algorithm: 'ecdsa-p256', format: 'pem' } })).toMatchObject({ status: 409, body: { error: { code: 'certificate_not_renewable' } } })

    const stats = (await viewer.rpc('certificate_stats.get')).body.data
    expect(stats).toMatchObject({ active: 1, expiring_within_30_days: 1, imported_expiring_within_30_days: 1, issued_last_7_days: 0 })
    const events = await query()`select name, actor_type from events where name = 'certificates.import'`
    expect(events).toEqual([{ name: 'certificates.import', actor_type: 'user' }])
  })
})
