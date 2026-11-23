import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fetch, setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, confirmWithCode, query, resetState, serverOptions, setupAdmin } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('trust bundle tests: the openssl CLI is not installed, so the OpenSSL checks are skipped')

const none = { dns: [], ip: [], email: [] }

async function ok(client: Client, method: string, body: object) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

const blocks = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\n/g) ?? []

/** root → l2 → l3, and an admin (with an API key), operator and viewer. */
async function world() {
  const admin = await setupAdmin()
  const operator = await addUser(admin, 'op@example.com', 'operator')
  const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
  const adminKey = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
  const ca = (body: object) => ok(admin, 'certificate_authorities.create', body)
  const root = await ca({ signing: 'self_signed', name: 'Root', slug: 'root', subject: [{ type: 'CN', value: 'Bundle Root' }], validity_days: 3650, path_length: 2 })
  const internal = (parent: string, slug: string, path_length: number, validity_days: number) => ({
    signing: 'internal',
    parent_ca_id: parent,
    name: slug.toUpperCase(),
    slug,
    subject: [{ type: 'CN', value: `Bundle ${slug}` }],
    validity_days,
    path_length,
    name_constraints: { permitted: { ...none, dns: ['example.test'] }, excluded: none },
  })
  const l2 = await ca(internal(root.id, 'l2', 1, 365))
  const l3 = await ca(internal(l2.id, 'l3', 0, 300))
  return { admin, operator, viewer, adminKey, root, l2, l3 }
}

describe('trust bundles', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('lets every role read, and only an admin with a fresh session change them', async () => {
    const w = await world()
    const body = { name: 'Clients', slug: 'clients', ca_ids: [w.l3.id] }
    expect((await w.viewer.rpc('trust_bundles.create', body)).status).toBe(403)
    expect((await w.operator.rpc('trust_bundles.create', body)).status).toBe(403)
    expect((await new Client().rpcWithKey(w.adminKey, 'trust_bundles.create', body)).status).toBe(403)
    await ageSessions(30)
    expect((await w.admin.rpc('trust_bundles.create', body)).body.error.code).toBe('reauth_required')
    await confirmWithCode(w.admin, 'admin@example.com')

    const created = await ok(w.admin, 'trust_bundles.create', body)
    expect(created).toMatchObject({ slug: 'clients', include_chain: false, url: `${process.env.URL}/api/pki/bundle/clients.pem`, permissions: { update: true, delete: true } })
    expect((await w.admin.rpc('trust_bundles.create', body)).body.error.code).toBe('slug_taken')
    expect((await w.admin.rpc('trust_bundles.create', { ...body, slug: 'Bad Slug' })).body.error.code).toBe('invalid_slug')
    expect((await w.admin.rpc('trust_bundles.create', { ...body, slug: 'other', ca_ids: [crypto.randomUUID()] })).status).toBe(404)

    for (const client of [w.viewer, w.operator]) {
      expect((await client.rpc('trust_bundles.list')).body.data.map((b: { slug: string }) => b.slug)).toEqual(['clients'])
      const got = await client.rpc('trust_bundles.get', { id: created.id })
      expect(got.body.data.permissions).toEqual({ read: true, update: false, delete: false })
      expect((await client.rpc('trust_bundles.update', { id: created.id, include_chain: true })).status).toBe(403)
      expect((await client.rpc('trust_bundles.delete', { id: created.id })).status).toBe(403)
    }

    expect((await w.admin.rpc('trust_bundles.delete', { id: created.id })).status).toBe(200)
    expect((await new Client().get('/api/pki/bundle/clients.pem')).status).toBe(404)
    const events = await query()`select name from events where name like 'trust_bundles.%' order by created_at`
    expect(events.map((e) => e.name)).toEqual(['trust_bundles.create', 'trust_bundles.delete'])
  })

  describe.skipIf(!hasOpenssl)('with OpenSSL', () => {
    const dir = mkdtempSync(join(tmpdir(), 'certifly-bundle-test-'))
    afterAll(() => rmSync(dir, { recursive: true, force: true }))
    const openssl = (args: string[]) => {
      const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' })
      if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
      return result.stdout
    }

    it('serves exactly the chosen certificates, plus the chain when asked, as PEM that OpenSSL parses', async () => {
      const w = await world()
      const bundle = await ok(w.admin, 'trust_bundles.create', { name: 'Issuing', slug: 'issuing', ca_ids: [w.l3.id, w.root.id] })
      const fetchPem = async () => {
        const response = await new Client().get('/api/pki/bundle/issuing.pem')
        expect(response.status).toBe(200)
        expect(response.headers.get('content-type')).toBe('application/pem-certificate-chain')
        expect(response.headers.get('cache-control')).toMatch(/^public, max-age=\d+$/)
        return response.text()
      }
      // In the order picked, and nothing else.
      expect(blocks(await fetchPem())).toEqual([w.l3.active_certificate.pem, w.root.active_certificate.pem])
      expect(bundle.certificates.map((c: { from_chain: boolean }) => c.from_chain)).toEqual([false, false])

      const withChain = await ok(w.admin, 'trust_bundles.update', { id: bundle.id, include_chain: true })
      expect(withChain.certificates.map((c: { subject: string; from_chain: boolean }) => [c.subject, c.from_chain])).toEqual([
        ['CN=Bundle l3', false],
        ['CN=Bundle Root', false],
        ['CN=Bundle l2', true],
      ])
      const pem = await fetchPem()
      // The root is picked and also in l3's chain: it appears once.
      expect(blocks(pem)).toEqual([w.l3.active_certificate.pem, w.root.active_certificate.pem, w.l2.active_certificate.pem])

      writeFileSync(join(dir, 'bundle.pem'), pem)
      openssl(['crl2pkcs7', '-nocrl', '-certfile', 'bundle.pem', '-out', 'bundle.p7b'])
      const subjects = openssl(['pkcs7', '-in', 'bundle.p7b', '-print_certs', '-noout'])
        .split('\n')
        .filter((line) => line.startsWith('subject='))
      expect(subjects).toHaveLength(3)
      expect(subjects.join('\n')).toMatch(/Bundle l3[\s\S]*Bundle Root[\s\S]*Bundle l2/)

      // The bundle verifies l3 on its own as a trust store.
      writeFileSync(join(dir, 'l3.pem'), w.l3.active_certificate.pem)
      expect(openssl(['verify', '-CAfile', 'bundle.pem', 'l3.pem'])).toContain('l3.pem: OK')
    })
  })

  describe('Traefik configuration', () => {
    const yamlUrl = (slug: string) => `/api/pki/bundle/${slug}/traefik.yml`
    const jsonUrl = (slug: string) => `/api/pki/bundle/${slug}/traefik.json`

    /** The PEM blocks of a YAML literal-block list, with the list indentation removed. */
    const yamlBlocks = (yaml: string, key: string) => {
      const out: string[] = []
      const lines = yaml.split('\n')
      const start = lines.findIndex((line) => line.trim() === `${key}:`)
      const indent = lines[start]!.length - lines[start]!.trimStart().length
      let current: string[] | null = null
      for (const line of lines.slice(start + 1)) {
        const pad = line.length - line.trimStart().length
        if (!line.trim()) continue
        if (pad <= indent) break
        if (line.trim() === '- |') {
          current = []
          out.push('')
        } else if (current) {
          out[out.length - 1] += `${line.trim()}\n`
        }
      }
      return out
    }

    it('answers 404 for a missing bundle and for one with Traefik off, without telling them apart', async () => {
      const w = await world()
      await ok(w.admin, 'trust_bundles.create', { name: 'Off', slug: 'off', ca_ids: [w.l3.id] })
      const off = await new Client().get(yamlUrl('off'))
      const missing = await new Client().get(yamlUrl('nothing-here'))
      expect([off.status, missing.status]).toEqual([404, 404])
      // The error body names the requested path, nothing else may differ.
      const body = async (response: Response) => ({ ...(await response.json()), url: undefined })
      expect(await body(off)).toEqual(await body(missing))
      expect((await new Client().get(jsonUrl('off'))).status).toBe(404)
      // The PEM stays public either way, and other file names are not routes.
      expect((await new Client().get('/api/pki/bundle/off.pem')).status).toBe(200)
      expect((await new Client().get('/api/pki/bundle/off/other.yml')).status).toBe(404)
    })

    it('has Traefik off by default and shows the settings', async () => {
      const w = await world()
      const created = await ok(w.admin, 'trust_bundles.create', { name: 'Plain', slug: 'plain', ca_ids: [w.l3.id] })
      expect(created).toMatchObject({
        traefik_enabled: false,
        traefik_client_auth: true,
        traefik_client_auth_type: 'RequireAndVerifyClientCert',
        traefik_tls_option_name: null,
        traefik_servers_transport: true,
        traefik_servers_transport_name: null,
        traefik_require_token: false,
        traefik_url: `${process.env.URL}/api/pki/bundle/plain/traefik.yml`,
        traefik_refs: { tls_option: 'plain-mtls@http', servers_transport: 'plain@http' },
      })
    })

    it('serves the bundle certificates with custom names, as YAML and as JSON', async () => {
      const w = await world()
      const bundle = await ok(w.admin, 'trust_bundles.create', {
        name: 'Edge',
        slug: 'edge',
        ca_ids: [w.l3.id, w.root.id],
        traefik_enabled: true,
        traefik_tls_option_name: 'clients',
        traefik_servers_transport_name: 'backends',
        traefik_client_auth_type: 'VerifyClientCertIfGiven',
      })
      expect(bundle.traefik_refs).toEqual({ tls_option: 'clients@http', servers_transport: 'backends@http' })
      const expected = [w.l3.active_certificate.pem, w.root.active_certificate.pem]
      const pem = blocks(await (await new Client().get('/api/pki/bundle/edge.pem')).text())
      expect(pem).toEqual(expected)

      const response = await new Client().get(yamlUrl('edge'))
      expect(response.status).toBe(200)
      expect(response.headers.get('content-type')).toBe('application/yaml')
      expect(response.headers.get('cache-control')).toBe('no-cache')
      const yaml = await response.text()
      expect(yaml).toMatch(/^tls:\n {2}options:\n {4}clients:\n {6}minVersion: VersionTLS12\n {6}clientAuth:\n {8}caFiles:\n/)
      expect(yaml).toContain('        clientAuthType: VerifyClientCertIfGiven\n')
      expect(yaml).toContain('http:\n  serversTransports:\n    backends:\n      rootCAs:\n')
      expect(yamlBlocks(yaml, 'caFiles')).toEqual(expected)
      expect(yamlBlocks(yaml, 'rootCAs')).toEqual(expected)

      const json = await new Client().get(jsonUrl('edge'))
      expect(json.headers.get('content-type')).toBe('application/json')
      expect(await json.json()).toEqual({
        tls: { options: { clients: { minVersion: 'VersionTLS12', clientAuth: { caFiles: expected, clientAuthType: 'VerifyClientCertIfGiven' } } } },
        http: { serversTransports: { backends: { rootCAs: expected } } },
      })
    })

    it('follows the chosen parts and the default names, and picks up changes to the bundle', async () => {
      const w = await world()
      const bundle = await ok(w.admin, 'trust_bundles.create', { name: 'Parts', slug: 'parts', ca_ids: [w.l3.id], traefik_enabled: true, traefik_servers_transport: false })
      let yaml = await (await new Client().get(yamlUrl('parts'))).text()
      expect(yaml).toContain('    parts-mtls:\n')
      expect(yaml).not.toContain('serversTransports')
      await ok(w.admin, 'trust_bundles.update', { id: bundle.id, traefik_client_auth: false, traefik_servers_transport: true, include_chain: true })
      yaml = await (await new Client().get(yamlUrl('parts'))).text()
      expect(yaml).not.toContain('tls:')
      expect(yaml).toContain('    parts:\n      rootCAs:\n')
      expect(yamlBlocks(yaml, 'rootCAs')).toEqual([w.l3.active_certificate.pem, w.l2.active_certificate.pem, w.root.active_certificate.pem])
      // A blank name goes back to the default.
      await ok(w.admin, 'trust_bundles.update', { id: bundle.id, traefik_servers_transport_name: 'x' })
      expect(await (await new Client().get(yamlUrl('parts'))).text()).toContain('    x:\n')
      await ok(w.admin, 'trust_bundles.update', { id: bundle.id, traefik_servers_transport_name: ' ' })
      expect(await (await new Client().get(yamlUrl('parts'))).text()).toContain('    parts:\n')
      await ok(w.admin, 'trust_bundles.update', { id: bundle.id, traefik_enabled: false })
      expect((await new Client().get(yamlUrl('parts'))).status).toBe(404)
      const events = await query()`select data from events where name = 'trust_bundles.update' order by created_at`
      expect((events.at(0)!.data as { changed: string[] }).changed.sort()).toEqual(['include_chain', 'traefik_client_auth', 'traefik_servers_transport'])
    })

    it('asks for the bundle token when the bundle requires one', async () => {
      const w = await world()
      const created = await ok(w.admin, 'trust_bundles.create', { name: 'Locked', slug: 'locked', ca_ids: [w.l3.id], traefik_enabled: true, traefik_require_token: true })
      const token = created.traefik_token as string
      expect(token).toMatch(/^tb_[A-Za-z0-9_-]{43}$/)
      const get = (path: string, authorization?: string) => fetch(path, { headers: authorization ? { authorization } : {} })

      const none = await get(yamlUrl('locked'))
      expect(none.status).toBe(401)
      expect(none.headers.get('www-authenticate')).toBe('Bearer')
      expect((await get(yamlUrl('locked'), 'Bearer tb_wrong')).status).toBe(403)
      expect((await get(yamlUrl('locked'), 'Bearer nonsense')).status).toBe(403)
      expect((await get(yamlUrl('locked'), `Basic ${token}`)).status).toBe(401)
      // API keys and browser sessions are not the token.
      expect((await get(yamlUrl('locked'), `Bearer ${w.adminKey}`)).status).toBe(403)
      expect((await w.admin.get(yamlUrl('locked'))).status).toBe(401)

      const valid = await get(yamlUrl('locked'), `Bearer ${token}`)
      expect(valid.status).toBe(200)
      expect(await valid.text()).toContain('caFiles:')
      expect((await get(jsonUrl('locked'), `Bearer ${token}`)).status).toBe(200)
      // The token belongs to this bundle only.
      const other = await ok(w.admin, 'trust_bundles.create', { name: 'Other', slug: 'other', ca_ids: [w.l3.id], traefik_enabled: true, traefik_require_token: true })
      expect((await get(yamlUrl('other'), `Bearer ${token}`)).status).toBe(403)
      expect((await get(yamlUrl('other'), `Bearer ${other.traefik_token}`)).status).toBe(200)
      // A missing or disabled bundle is 404 with or without a token.
      expect((await get(yamlUrl('missing'), `Bearer ${token}`)).status).toBe(404)

      // The token is shown once: reading the bundle never returns it, and only a hash is stored.
      for (const client of [w.admin, w.viewer]) {
        expect((await client.rpc('trust_bundles.get', { id: created.id })).body.data.traefik_token).toBeNull()
        expect(JSON.stringify((await client.rpc('trust_bundles.list')).body)).not.toContain(token)
      }
      const [row] = await query()`select traefik_token_hash from trust_bundles where id = ${created.id}`
      expect(row!.traefik_token_hash).toMatch(/^[0-9a-f]{64}$/)
      expect(row!.traefik_token_hash).not.toContain(token)
    })

    it('replaces the token when it is regenerated, and drops it when no longer required', async () => {
      const w = await world()
      const get = (path: string, token: string) => fetch(path, { headers: { authorization: `Bearer ${token}` } })
      // Turning the requirement on later generates the first token; saving again keeps it.
      const bundle = await ok(w.admin, 'trust_bundles.create', { name: 'Late', slug: 'late', ca_ids: [w.l3.id], traefik_enabled: true })
      expect(bundle.traefik_token).toBeNull()
      expect((await new Client().get(yamlUrl('late'))).status).toBe(200)
      const turnedOn = await ok(w.admin, 'trust_bundles.update', { id: bundle.id, traefik_require_token: true })
      const first = turnedOn.traefik_token as string
      expect(first).toMatch(/^tb_/)
      expect((await new Client().get(yamlUrl('late'))).status).toBe(401)
      expect((await get(yamlUrl('late'), first)).status).toBe(200)
      expect((await ok(w.admin, 'trust_bundles.update', { id: bundle.id, name: 'Late one' })).traefik_token).toBeNull()
      expect((await get(yamlUrl('late'), first)).status).toBe(200)

      expect((await w.operator.rpc('trust_bundles.regenerate_traefik_token', { id: bundle.id })).status).toBe(403)
      expect((await new Client().rpcWithKey(w.adminKey, 'trust_bundles.regenerate_traefik_token', { id: bundle.id })).status).toBe(403)
      expect((await get(yamlUrl('late'), first)).status).toBe(200)
      const second = (await ok(w.admin, 'trust_bundles.regenerate_traefik_token', { id: bundle.id })).traefik_token as string
      expect(second).toMatch(/^tb_/)
      expect(second).not.toBe(first)
      expect((await get(yamlUrl('late'), first)).status).toBe(403)
      expect((await get(yamlUrl('late'), second)).status).toBe(200)

      await ageSessions(30)
      expect((await w.admin.rpc('trust_bundles.regenerate_traefik_token', { id: bundle.id })).body.error.code).toBe('reauth_required')
      await confirmWithCode(w.admin, 'admin@example.com')

      // Without the requirement there is no token to regenerate, and the hash is gone.
      await ok(w.admin, 'trust_bundles.update', { id: bundle.id, traefik_require_token: false })
      const [row] = await query()`select traefik_token_hash from trust_bundles where id = ${bundle.id}`
      expect(row!.traefik_token_hash).toBeNull()
      expect((await w.admin.rpc('trust_bundles.regenerate_traefik_token', { id: bundle.id })).body.error.code).toBe('traefik_token_not_required')
      expect((await get(yamlUrl('late'), second)).status).toBe(200)
      const events = await query()`select name, data from events where name like 'trust_bundles.%' order by created_at`
      expect(events.map((e) => e.name)).toEqual(['trust_bundles.create', 'trust_bundles.update', 'trust_bundles.update', 'trust_bundles.regenerate_traefik_token', 'trust_bundles.update'])
      expect(JSON.stringify(events)).not.toContain(second)
    })

    it('refuses settings that cannot work', async () => {
      const w = await world()
      const base = { name: 'Bad', slug: 'bad', ca_ids: [w.l3.id] }
      const code = async (extra: object) => (await w.admin.rpc('trust_bundles.create', { ...base, ...extra })).body.error.code
      expect(await code({ traefik_tls_option_name: 'has space' })).toBe('invalid_traefik_tls_option_name')
      expect(await code({ traefik_tls_option_name: '-leading' })).toBe('invalid_traefik_tls_option_name')
      expect(await code({ traefik_tls_option_name: 'a'.repeat(64) })).toBe('validation_error')
      expect(await code({ traefik_servers_transport_name: 'dots.not.allowed' })).toBe('invalid_traefik_servers_transport_name')
      expect(await code({ traefik_servers_transport_name: 'x@http' })).toBe('invalid_traefik_servers_transport_name')
      expect(await code({ traefik_client_auth_type: 'NoClientCert' })).toBe('validation_error')
      expect(await code({ traefik_enabled: true, traefik_client_auth: false, traefik_servers_transport: false })).toBe('traefik_target_required')
      // Nothing was created by the refusals; with Traefik off, both parts may be off.
      expect((await w.admin.rpc('trust_bundles.list')).body.data).toEqual([])
      const created = await ok(w.admin, 'trust_bundles.create', { ...base, traefik_client_auth: false, traefik_servers_transport: false })
      expect(created.traefik_enabled).toBe(false)
      // Turning it on checks the settings the bundle has after the change.
      const update = (extra: object) => w.admin.rpc('trust_bundles.update', { id: created.id, ...extra })
      expect((await update({ traefik_enabled: true })).body.error.code).toBe('traefik_target_required')
      expect((await update({ traefik_enabled: true, traefik_servers_transport: true, traefik_servers_transport_name: 'ok_name-1' })).status).toBe(200)
      expect((await update({ traefik_servers_transport: false })).body.error.code).toBe('traefik_target_required')
      expect((await update({ traefik_tls_option_name: 'bad name' })).body.error.code).toBe('invalid_traefik_tls_option_name')
      // Operators and viewers cannot change the settings.
      expect((await w.operator.rpc('trust_bundles.update', { id: created.id, traefik_enabled: false })).status).toBe(403)
    })
  })
})
