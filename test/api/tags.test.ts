import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, query, resetState, serverOptions, setupAdmin } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('tag tests: the openssl CLI is not installed, so the OpenSSL extended key usage check is skipped')

const none = { dns: [], ip: [], email: [] }
const DAY = 86400

async function ok(client: Client, method: string, body: object = {}) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

const names = (cert: { tags: { name: string }[] }) => cert.tags.map((t) => t.name)
const ids = (rows: { id: string }[]) => rows.map((r) => r.id)

/** An admin, operator (with an API key) and viewer, a root, an issuing CA and a client template. */
async function world() {
  const admin = await setupAdmin()
  const operator = await addUser(admin, 'op@example.com', 'operator')
  const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
  const operatorKey = (await operator.rpc('api_keys.create', { name: 'automation' })).body.data.secret as string
  const adminKey = (await admin.rpc('api_keys.create', { name: 'admin automation' })).body.data.secret as string
  const root = await ok(admin, 'certificate_authorities.create', { signing: 'self_signed', name: 'Root', slug: 'root', subject: [{ type: 'CN', value: 'Tag Root' }], validity_days: 3650, path_length: 1 })
  const issuing = await ok(admin, 'certificate_authorities.create', {
    signing: 'internal',
    parent_ca_id: root.id,
    name: 'Issuing',
    slug: 'issuing',
    subject: [{ type: 'CN', value: 'Tag Issuing CA' }],
    validity_days: 365,
    path_length: 0,
    name_constraints: { permitted: { ...none, dns: ['example.test'] }, excluded: none },
  })
  const template = await ok(admin, 'templates.create', { preset: 'mtls_client', name: 'Clients', slug: 'clients', ca_id: issuing.id, allowed_dns: ['example.test', '**.example.test'], max_ttl_seconds: 300 * DAY })
  return { admin, operator, viewer, operatorKey, adminKey, root, issuing, template }
}
type World = Awaited<ReturnType<typeof world>>

const keygen = { algorithm: 'ecdsa-p256', format: 'pem' }
async function issue(w: World, common_name: string, extra: Record<string, unknown> = {}, template_id = w.template.id) {
  return (await ok(w.operator, 'certificates.issue', { template_id, keygen, common_name, ...extra })).certificate
}

/** A certificate from outside: issued here, its row dropped, then imported back as inventory. */
async function importedCertificate(w: World, common_name: string, tag_ids?: string[]) {
  const cert = await issue(w, common_name, { tag_ids: [] })
  await query()`delete from certificates where id = ${cert.id}`
  const result = await ok(w.operator, 'certificates.import', { pem: cert.pem, ...(tag_ids ? { tag_ids } : {}) })
  return result.imported[0] as { id: string }
}

describe('tags', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  describe('managed list', () => {
    it('lets every role read, and only a recently confirmed admin session manage', async () => {
      const w = await world()
      const created = await ok(w.admin, 'tags.create', { name: 'Production', color: 'green' })
      expect(created).toMatchObject({ name: 'Production', color: 'green', certificate_count: 0, template_count: 0, permissions: { read: true, update: true, delete: true } })

      for (const client of [w.viewer, w.operator]) {
        expect((await client.rpc('tags.list')).body.data.map((t: { name: string }) => t.name)).toEqual(['Production'])
        expect((await client.rpc('tags.create', { name: 'Mine', color: 'blue' })).body.error.code).toBe('forbidden')
        expect((await client.rpc('tags.update', { id: created.id, name: 'Other' })).body.error.code).toBe('forbidden')
        expect((await client.rpc('tags.delete', { id: created.id })).body.error.code).toBe('forbidden')
      }
      expect((await w.viewer.rpc('tags.list')).body.data[0].permissions).toEqual({ read: true, update: false, delete: false })

      const key = new Client()
      expect((await key.rpcWithKey(w.adminKey, 'tags.list')).status).toBe(200)
      expect((await key.rpcWithKey(w.adminKey, 'tags.create', { name: 'Via key', color: 'blue' })).body.error.code).toBe('forbidden')
      expect((await key.rpcWithKey(w.adminKey, 'tags.delete', { id: created.id })).body.error.code).toBe('forbidden')

      await ageSessions(11)
      expect((await w.admin.rpc('tags.create', { name: 'Stale', color: 'blue' })).body.error.code).toBe('reauth_required')
      expect((await w.admin.rpc('tags.update', { id: created.id, color: 'pink' })).body.error.code).toBe('reauth_required')
      expect((await w.admin.rpc('tags.delete', { id: created.id })).body.error.code).toBe('reauth_required')
      await query()`update sessions set reauth_at = now()`

      expect(await ok(w.admin, 'tags.update', { id: created.id, name: 'Prod', color: 'teal' })).toMatchObject({ name: 'Prod', color: 'teal' })
      expect(await ok(w.admin, 'tags.delete', { id: created.id })).toEqual({ removed_from_certificates: 0, removed_from_templates: 0 })
      expect((await w.admin.rpc('tags.list')).body.data).toEqual([])
      const events = await query()`select name from events where name like 'tags.%' order by created_at`
      expect(events.map((e) => e.name)).toEqual(['tags.create', 'tags.update', 'tags.delete'])
    })

    it('reports the tag permissions on the instance', async () => {
      const w = await world()
      const perms = async (client: Client) => (await client.rpc('sessions.get')).body.data.instance.permissions
      expect(await perms(w.admin)).toMatchObject({ read_tags: true, manage_tags: true, update_certificate_tags: true })
      expect(await perms(w.operator)).toMatchObject({ read_tags: true, manage_tags: false, update_certificate_tags: true })
      expect(await perms(w.viewer)).toMatchObject({ read_tags: true, manage_tags: false, update_certificate_tags: false })
    })

    it('refuses a duplicate name in any case and an unknown colour', async () => {
      const w = await world()
      const tag = await ok(w.admin, 'tags.create', { name: 'Production', color: 'green' })
      const other = await ok(w.admin, 'tags.create', { name: 'Staging', color: 'yellow' })
      expect(await w.admin.rpc('tags.create', { name: 'production', color: 'blue' })).toMatchObject({ status: 409, body: { error: { code: 'tag_name_taken' } } })
      expect((await w.admin.rpc('tags.create', { name: ' PRODUCTION ', color: 'blue' })).body.error.code).toBe('tag_name_taken')
      expect((await w.admin.rpc('tags.update', { id: other.id, name: 'PRODUCTION' })).body.error.code).toBe('tag_name_taken')
      expect(await w.admin.rpc('tags.create', { name: 'Red', color: 'red' })).toMatchObject({ status: 400, body: { error: { code: 'invalid_tag_color' } } })
      expect((await w.admin.rpc('tags.update', { id: tag.id, color: '#ff0000' })).body.error.code).toBe('invalid_tag_color')
      expect((await w.admin.rpc('tags.create', { name: '   ', color: 'blue' })).body.error.code).toBe('invalid_tag_name')
      expect((await w.admin.rpc('tags.list')).body.data.map((t: { name: string; color: string }) => [t.name, t.color])).toEqual([
        ['Production', 'green'],
        ['Staging', 'yellow'],
      ])
    })
  })

  describe('templates and issuance', () => {
    it('copies the template default tags at issue unless tag_ids is given, and keeps them when the template changes', async () => {
      const w = await world()
      const prod = await ok(w.admin, 'tags.create', { name: 'prod', color: 'green' })
      const team = await ok(w.admin, 'tags.create', { name: 'team-a', color: 'blue' })
      const other = await ok(w.admin, 'tags.create', { name: 'other', color: 'gray' })
      const template = await ok(w.admin, 'templates.update', { id: w.template.id, tag_ids: [team.id, prod.id] })
      expect(template.tags).toEqual([
        { id: prod.id, name: 'prod', color: 'green' },
        { id: team.id, name: 'team-a', color: 'blue' },
      ])
      expect((await w.viewer.rpc('templates.list')).body.data[0].tags).toHaveLength(2)
      const created = await ok(w.admin, 'templates.create', { preset: 'mtls_client', name: 'More', slug: 'more', ca_id: w.issuing.id, allowed_dns: ['example.test'], tag_ids: [other.id] })
      expect(names(created)).toEqual(['other'])

      const copied = await issue(w, 'copied')
      expect(names(copied)).toEqual(['prod', 'team-a'])
      expect(names(await issue(w, 'explicit', { tag_ids: [other.id] }))).toEqual(['other'])
      expect(names(await issue(w, 'empty', { tag_ids: [] }))).toEqual([])
      expect(await w.operator.rpc('certificates.issue', { template_id: w.template.id, keygen, common_name: 'bad', tag_ids: [crypto.randomUUID()] })).toMatchObject({ status: 404, body: { error: { code: 'tag_not_found' } } })

      await ok(w.admin, 'templates.update', { id: w.template.id, tag_ids: [other.id] })
      expect(names(await ok(w.viewer, 'certificates.get', { id: copied.id }))).toEqual(['prod', 'team-a'])
      const listed = (await w.viewer.rpc('certificates.list', { query: 'copied' })).body.data[0]
      expect(names(listed)).toEqual(['prod', 'team-a'])

      // Renewing copies the old certificate's tags, not the template's current ones.
      const renewed = (await ok(w.operator, 'certificates.renew', { id: copied.id, keygen })).certificate
      expect(names(renewed)).toEqual(['prod', 'team-a'])
      const [event] = await query()`select data from events where name = 'certificates.renew'`
      expect([...event!.data.tag_ids].sort()).toEqual([prod.id, team.id].sort())
    })

    it('lets operators and their API keys edit tags, also on imported certificates, and refuses viewers', async () => {
      const w = await world()
      const a = await ok(w.admin, 'tags.create', { name: 'a', color: 'blue' })
      const b = await ok(w.admin, 'tags.create', { name: 'b', color: 'pink' })
      const cert = await issue(w, 'edit-me', { tag_ids: [a.id] })
      expect(cert.permissions.update_tags).toBe(true)

      expect(await w.viewer.rpc('certificates.update', { id: cert.id, tag_ids: [b.id] })).toMatchObject({ status: 403, body: { error: { code: 'forbidden' } } })
      expect((await w.viewer.rpc('certificates.get', { id: cert.id })).body.data.permissions.update_tags).toBe(false)

      const updated = await ok(w.operator, 'certificates.update', { id: cert.id, tag_ids: [b.id] })
      expect(names(updated)).toEqual(['b'])
      const [event] = await query()`select actor_type, data from events where name = 'certificates.update' and subject_id = ${cert.id}`
      expect(event).toMatchObject({ actor_type: 'user', data: { added_tag_ids: [b.id], removed_tag_ids: [a.id] } })

      const viaKey = await new Client().rpcWithKey(w.operatorKey, 'certificates.update', { id: cert.id, tag_ids: [a.id, b.id] })
      expect(viaKey.status).toBe(200)
      expect(names(viaKey.body.data)).toEqual(['a', 'b'])
      const [keyEvent] = await query()`select actor_type, data from events where name = 'certificates.update' and actor_type = 'api_key'`
      expect(keyEvent!.data).toMatchObject({ added_tag_ids: [a.id], removed_tag_ids: [] })
      expect((await w.operator.rpc('certificates.update', { id: crypto.randomUUID(), tag_ids: [] })).status).toBe(404)

      const imported = await importedCertificate(w, 'imported-one', [a.id])
      expect(names(await ok(w.viewer, 'certificates.get', { id: imported.id }))).toEqual(['a'])
      expect(names(await ok(w.operator, 'certificates.update', { id: imported.id, tag_ids: [b.id] }))).toEqual(['b'])
    })

    it('takes a deleted tag off every certificate and template', async () => {
      const w = await world()
      const gone = await ok(w.admin, 'tags.create', { name: 'gone', color: 'orange' })
      const kept = await ok(w.admin, 'tags.create', { name: 'kept', color: 'violet' })
      await ok(w.admin, 'templates.update', { id: w.template.id, tag_ids: [gone.id, kept.id] })
      const one = await issue(w, 'one')
      const two = await issue(w, 'two', { tag_ids: [gone.id] })
      expect((await w.admin.rpc('tags.list')).body.data[0]).toMatchObject({ name: 'gone', certificate_count: 2, template_count: 1 })

      expect(await ok(w.admin, 'tags.delete', { id: gone.id })).toEqual({ removed_from_certificates: 2, removed_from_templates: 1 })
      expect(names(await ok(w.viewer, 'certificates.get', { id: one.id }))).toEqual(['kept'])
      expect(names(await ok(w.viewer, 'certificates.get', { id: two.id }))).toEqual([])
      expect(names(await ok(w.viewer, 'templates.get', { id: w.template.id }))).toEqual(['kept'])
      const [event] = await query()`select data from events where name = 'tags.delete'`
      expect(event!.data).toMatchObject({ name: 'gone', removed_from_certificates: 2, removed_from_templates: 1 })
      expect((await w.admin.rpc('tags.delete', { id: gone.id })).status).toBe(404)
    })
  })

  describe('certificate list', () => {
    it('filters by all given tags and by untagged', async () => {
      const w = await world()
      const a = await ok(w.admin, 'tags.create', { name: 'a', color: 'blue' })
      const b = await ok(w.admin, 'tags.create', { name: 'b', color: 'green' })
      const both = await issue(w, 'both', { tag_ids: [a.id, b.id] })
      const onlyA = await issue(w, 'only-a', { tag_ids: [a.id] })
      const plain = await issue(w, 'plain', { tag_ids: [] })
      const list = async (body: object) => ids((await w.viewer.rpc('certificates.list', { sort: 'name', ...body })).body.data)
      expect(await list({ tag_ids: [a.id] })).toEqual([both.id, onlyA.id])
      expect(await list({ tag_ids: [a.id, b.id] })).toEqual([both.id])
      expect(await list({ tag_ids: [b.id, crypto.randomUUID()] })).toEqual([])
      expect(await list({ untagged: true })).toEqual([plain.id])
      expect(await list({ untagged: false })).toEqual([both.id, onlyA.id])
    })

    it('pages correctly when sorted by expiry, name or newest', async () => {
      const w = await world()
      // Names, and days to expiry, chosen so the three orders differ.
      const spec: [string, number][] = [
        ['delta', 40],
        ['alpha', 90],
        ['echo', 10],
        ['charlie', 70],
        ['bravo', 20],
      ]
      const certs: { id: string; name: string; days: number }[] = []
      for (const [name, days] of spec) {
        const cert = await issue(w, name)
        await query()`update certificates set not_after = now() + make_interval(days => ${days}) where id = ${cert.id}`
        certs.push({ id: cert.id, name, days })
      }
      async function all(sort: string) {
        const seen: string[] = []
        let cursor: string | undefined
        for (let i = 0; i < 10; i++) {
          const res = await w.viewer.rpc('certificates.list', { sort, limit: 2, ...(cursor ? { cursor } : {}) })
          expect(res.status).toBe(200)
          seen.push(...ids(res.body.data))
          cursor = res.body.next_cursor
          if (!cursor) break
        }
        return seen
      }
      const by = (compare: (x: (typeof certs)[number], y: (typeof certs)[number]) => number) => [...certs].sort(compare).map((c) => c.id)
      expect(await all('expiry')).toEqual(by((x, y) => x.days - y.days))
      expect(await all('name')).toEqual(by((x, y) => x.name.localeCompare(y.name)))
      expect(await all('newest')).toEqual([...certs].reverse().map((c) => c.id))
      // The older parameter name still sorts by expiry.
      expect(ids((await w.viewer.rpc('certificates.list', { order: 'expiry' })).body.data)).toEqual(by((x, y) => x.days - y.days))
      // A cursor from one sort is refused by another sort with different key types.
      const page = await w.viewer.rpc('certificates.list', { sort: 'name', limit: 2 })
      expect((await w.viewer.rpc('certificates.list', { sort: 'expiry', cursor: page.body.next_cursor })).body.error.code).toBe('invalid_cursor')
    })
  })

  describe('groups', () => {
    it('counts per tag, template, CA and status, and each group filter lists exactly its rows', async () => {
      const w = await world()
      const a = await ok(w.admin, 'tags.create', { name: 'a', color: 'blue' })
      const b = await ok(w.admin, 'tags.create', { name: 'b', color: 'green' })
      await ok(w.admin, 'tags.create', { name: 'unused', color: 'gray' })
      const servers = await ok(w.admin, 'templates.create', { preset: 'mtls_client', name: 'Another', slug: 'another', ca_id: w.issuing.id, allowed_dns: ['example.test'], max_ttl_seconds: 300 * DAY })

      const both = await issue(w, 'both', { tag_ids: [a.id, b.id], ttl_seconds: 200 * DAY })
      const onlyA = await issue(w, 'only-a', { tag_ids: [a.id], ttl_seconds: 10 * DAY })
      const plain = await issue(w, 'plain', { tag_ids: [], ttl_seconds: 200 * DAY }, servers.id)
      const expired = await issue(w, 'expired', { tag_ids: [b.id], ttl_seconds: 200 * DAY })
      await query()`update certificates set not_before = now() - interval '3 days', not_after = now() - interval '1 day' where id = ${expired.id}`
      const revoked = await issue(w, 'revoked', { tag_ids: [], ttl_seconds: 5 * DAY }, servers.id)
      await ok(w.operator, 'certificates.revoke', { id: revoked.id, reason: 'superseded' })
      const imported = await importedCertificate(w, 'imported', [a.id])
      // The imported certificate came from a 30-day template: it is expiring within 30 days.

      type Group = { key: string; label: string | null; color: string | null; count: number; expiring_within_30_days: number; filter: Record<string, unknown> }
      const groups = async (group_by: string, filters: object = {}) => (await ok(w.viewer, 'certificate_groups.list', { group_by, ...filters })) as Group[]
      const pick = (list: Group[]) => list.map((g) => [g.key, g.label, g.color, g.count, g.expiring_within_30_days])

      async function checkFilters(list: Group[], expected: Record<string, string[]>, base: object = {}) {
        for (const group of list) {
          const rows = ids((await w.viewer.rpc('certificates.list', { ...base, ...group.filter, limit: 200 })).body.data)
          expect(rows.sort(), `group ${group.key}`).toEqual([...expected[group.key]!].sort())
          expect(rows).toHaveLength(group.count)
        }
      }

      const byTag = await groups('tag')
      expect(pick(byTag)).toEqual([
        [a.id, 'a', 'blue', 3, 2],
        [b.id, 'b', 'green', 2, 0],
        ['untagged', null, null, 2, 0],
      ])
      expect(byTag.map((g) => g.filter)).toEqual([{ tag_ids: [a.id] }, { tag_ids: [b.id] }, { untagged: true }])
      await checkFilters(byTag, { [a.id]: [both.id, onlyA.id, imported.id], [b.id]: [both.id, expired.id], untagged: [plain.id, revoked.id] })

      const byTemplate = await groups('template')
      expect(pick(byTemplate)).toEqual([
        [servers.id, 'Another', null, 2, 0],
        [w.template.id, 'Clients', null, 3, 1],
        ['imported', null, null, 1, 1],
      ])
      expect(byTemplate.at(-1)!.filter).toEqual({ imported: true })
      await checkFilters(byTemplate, { [servers.id]: [plain.id, revoked.id], [w.template.id]: [both.id, onlyA.id, expired.id], imported: [imported.id] })

      const byCa = await groups('ca')
      expect(pick(byCa)).toEqual([
        [w.issuing.id, 'Issuing', null, 5, 1],
        ['imported', null, null, 1, 1],
      ])
      expect(byCa[0]!.filter).toEqual({ ca_id: w.issuing.id })
      await checkFilters(byCa, { [w.issuing.id]: [both.id, onlyA.id, plain.id, expired.id, revoked.id], imported: [imported.id] })

      const byStatus = await groups('status')
      expect(pick(byStatus)).toEqual([
        ['active', null, null, 4, 2],
        ['expired', null, null, 1, 0],
        ['revoked', null, null, 1, 0],
      ])
      await checkFilters(byStatus, { active: [both.id, onlyA.id, plain.id, imported.id], expired: [expired.id], revoked: [revoked.id] })

      // The list filters apply to the groups too, and group filters combine with them.
      const filtered = await groups('tag', { status: 'active' })
      expect(pick(filtered)).toEqual([
        [a.id, 'a', 'blue', 3, 2],
        [b.id, 'b', 'green', 1, 0],
        ['untagged', null, null, 1, 0],
      ])
      await checkFilters(filtered, { [a.id]: [both.id, onlyA.id, imported.id], [b.id]: [both.id], untagged: [plain.id] }, { status: 'active' })
      expect((await w.viewer.rpc('certificate_groups.list', { group_by: 'owner' })).status).toBe(400)
    })
  })

  describe('extended key usages', () => {
    it('gives the presets their usages and refuses an empty list', async () => {
      const w = await world()
      const presets = (await ok(w.viewer, 'template_presets.list')) as { id: string; extended_key_usages: string[] }[]
      expect(Object.fromEntries(presets.map((p) => [p.id, p.extended_key_usages]))).toEqual({
        webserver_tls: ['server_auth'],
        mtls_server: ['server_auth'],
        mtls_client: ['client_auth'],
        server_client: ['server_auth', 'client_auth'],
      })
      expect(presets.every((p) => !('kind' in p))).toBe(true)
      const empty = await w.admin.rpc('templates.create', { preset: 'mtls_client', name: 'Empty', slug: 'empty', ca_id: w.issuing.id, allowed_dns: ['example.test'], extended_key_usages: [] })
      expect(empty).toMatchObject({ status: 400, body: { error: { code: 'invalid_extended_key_usages' } } })
      expect((await w.admin.rpc('templates.update', { id: w.template.id, extended_key_usages: [] })).body.error.code).toBe('invalid_extended_key_usages')
      expect((await w.admin.rpc('templates.update', { id: w.template.id, extended_key_usages: ['custom'] })).status).toBe(400)
    })

    it.skipIf(!hasOpenssl)('issues code signing and email protection from the template, as OpenSSL reads them', async () => {
      const w = await world()
      const template = await ok(w.admin, 'templates.create', {
        preset: 'mtls_client',
        name: 'Signing',
        slug: 'signing',
        ca_id: w.issuing.id,
        allowed_dns: ['example.test'],
        extended_key_usages: ['code_signing', 'email_protection'],
      })
      expect(template).toMatchObject({ extended_key_usages: ['code_signing', 'email_protection'], usage_hint: 'other' })
      const cert = await issue(w, 'signer', {}, template.id)
      expect(cert.extended_key_usages).toEqual(['code_signing', 'email_protection'])
      expect(cert.details.extended_key_usage_names).toEqual(['code_signing', 'email_protection'])

      const dir = mkdtempSync(join(tmpdir(), 'certifly-eku-test-'))
      try {
        writeFileSync(join(dir, 'cert.pem'), cert.pem)
        const result = spawnSync('openssl', ['x509', '-in', 'cert.pem', '-noout', '-text'], { cwd: dir, encoding: 'utf8' })
        expect(result.status).toBe(0)
        expect(result.stdout).toMatch(/X509v3 Extended Key Usage:\s+Code Signing, E-mail Protection\n/)
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    })
  })
})
