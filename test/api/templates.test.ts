import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, query, resetState, serverOptions, setupAdmin } from '../helpers'

const none = { dns: [], ip: [], email: [] }
const subject = (cn: string) => [{ type: 'CN', value: cn }]
const rootBody = (slug = 'root') => ({ signing: 'self_signed', name: `Root ${slug}`, slug, subject: subject(`Test Root ${slug}`), validity_days: 3650, path_length: 2 })
const issuingBody = (parent_ca_id: string, slug = 'issuing') => ({
  signing: 'internal',
  parent_ca_id,
  name: `CA ${slug}`,
  slug,
  subject: subject(`Test ${slug}`),
  validity_days: 365,
  path_length: 0,
  name_constraints: { permitted: { ...none, dns: ['example.test'], ip: ['10.0.0.0/8'] }, excluded: { ...none, dns: ['secret.example.test'] } },
})
const templateBody = (ca_id: string, slug = 'web', overrides: Record<string, unknown> = {}) => ({
  preset: 'webserver_tls',
  name: `Template ${slug}`,
  slug,
  ca_id,
  allowed_dns: ['**.example.test'],
  ...overrides,
})

describe('templates', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  async function ok(client: Client, method: string, body: object) {
    const res = await client.rpc(method, body)
    if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
    return res.body.data
  }

  /** An admin, operator and viewer, an admin API key, a root, an issuing CA below it and one template. */
  async function world() {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const key = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
    const root = await ok(admin, 'certificate_authorities.create', rootBody())
    const issuing = await ok(admin, 'certificate_authorities.create', issuingBody(root.id))
    const template = await ok(admin, 'templates.create', templateBody(issuing.id))
    return { admin, operator, viewer, key, root, issuing, template }
  }
  type World = Awaited<ReturnType<typeof world>>
  const mutations: [string, (w: World) => [string, object]][] = [
    ['create', (w) => ['templates.create', templateBody(w.issuing.id, 'another')]],
    ['update', (w) => ['templates.update', { id: w.template.id, name: 'Renamed', default_ttl_seconds: 30 * 86400 }]],
    ['archive', (w) => ['templates.archive', { id: w.template.id }]],
  ]

  describe('permissions', () => {
    it('lets every role and API keys read templates and presets', async () => {
      const w = await world()
      for (const client of [w.admin, w.operator, w.viewer]) {
        expect((await client.rpc('templates.list')).body.data.map((t: { slug: string }) => t.slug)).toEqual(['web'])
        expect((await client.rpc('templates.get', { id: w.template.id })).status).toBe(200)
        expect((await client.rpc('template_presets.list')).body.data.map((p: { id: string }) => p.id)).toEqual(['webserver_tls', 'mtls_server', 'mtls_client', 'server_client'])
      }
      const viaKey = await new Client().rpcWithKey(w.key, 'templates.get', { id: w.template.id })
      expect(viaKey.status).toBe(200)
      expect(viaKey.body.data.permissions).toEqual({ read: true, update: false, archive: false, issue: true })
      expect((await w.viewer.rpc('templates.get', { id: w.template.id })).body.data.permissions).toEqual({ read: true, update: false, archive: false, issue: false })
      expect((await w.operator.rpc('templates.get', { id: w.template.id })).body.data.permissions).toEqual({ read: true, update: false, archive: false, issue: true })
      expect((await w.admin.rpc('templates.get', { id: w.template.id })).body.data.permissions).toEqual({ read: true, update: true, archive: true, issue: true })
      expect((await w.viewer.rpc('templates.get', { id: crypto.randomUUID() })).status).toBe(404)
    })

    it('refuses viewers and operators', async () => {
      const w = await world()
      for (const [who, client] of [['viewer', w.viewer], ['operator', w.operator]] as const) {
        for (const [label, action] of mutations) {
          const [method, body] = action(w)
          const { status, body: answer } = await client.rpc(method, body)
          expect({ who, label, status, code: answer.error?.code }).toEqual({ who, label, status: 403, code: 'forbidden' })
        }
      }
    })

    it('refuses API keys, even an admin’s', async () => {
      const w = await world()
      for (const [label, action] of mutations) {
        const [method, body] = action(w)
        const { status, body: answer } = await new Client().rpcWithKey(w.key, method, body)
        expect({ label, status, code: answer.error?.code }).toEqual({ label, status: 403, code: 'forbidden' })
      }
    })

    it('asks an admin whose session has not confirmed it lately to do so, and changes nothing', async () => {
      const w = await world()
      await ageSessions(11)
      for (const [label, action] of mutations) {
        const [method, body] = action(w)
        const { status, body: answer } = await w.admin.rpc(method, body)
        expect({ label, status, code: answer.error?.code }).toEqual({ label, status: 403, code: 'reauth_required' })
      }
      const [row] = await query()`select name, status from templates where id = ${w.template.id}`
      expect(row).toEqual({ name: 'Template web', status: 'active' })
      const [{ n }] = await query()`select count(*)::int as n from templates`
      expect(n).toBe(1)
    })

    it('lets an admin with a fresh session create, update and archive, and records each', async () => {
      const w = await world()
      for (const [label, action] of mutations) {
        const [method, body] = action(w)
        const { status } = await w.admin.rpc(method, body)
        expect({ label, status }).toEqual({ label, status: 200 })
      }
      const template = (await w.admin.rpc('templates.get', { id: w.template.id })).body.data
      expect(template).toMatchObject({ name: 'Renamed', default_ttl_seconds: 30 * 86400, status: 'archived', permissions: { update: false, archive: false, issue: false } })
      expect((await w.admin.rpc('templates.archive', { id: w.template.id })).status).toBe(200)
      expect((await w.admin.rpc('templates.update', { id: w.template.id, name: 'Again' })).body.error.code).toBe('template_archived')
      const names = (await w.admin.rpc('events.list', { subject_type: 'template' })).body.data.map((e: { name: string }) => e.name)
      expect(names.sort()).toEqual(['templates.archive', 'templates.create', 'templates.create', 'templates.update'])
    })
  })

  describe('validation', () => {
    it('fills settings from the preset and adds keyEncipherment for RSA only', async () => {
      const w = await world()
      expect(w.template).toMatchObject({
        usage_hint: 'server',
        allowed_dns: ['**.example.test'],
        allowed_san_types: ['dns'],
        require_san: true,
        key_usages: ['digital_signature', 'key_encipherment'],
        extended_key_usages: ['server_auth'],
        bound_to_root: false,
        ca: { id: w.issuing.id, slug: 'issuing' },
      })
      const client = await ok(w.admin, 'templates.create', templateBody(w.issuing.id, 'clients', { preset: 'mtls_client', allowed_dns: ['example.test'] }))
      expect(client).toMatchObject({ usage_hint: 'client', key_usages: ['digital_signature'], extended_key_usages: ['client_auth'], require_common_name: true, require_san: false })
      const missing = await w.admin.rpc('templates.create', { name: 'Bare', slug: 'bare', ca_id: w.issuing.id, allowed_dns: ['example.test'] })
      expect(missing.status).toBe(400)
    })

    it('refuses rules outside the CA’s name constraints, on create and update', async () => {
      const w = await world()
      const outside = await w.admin.rpc('templates.create', templateBody(w.issuing.id, 'outside', { allowed_dns: ['**.example.test', 'other.test'], allowed_san_types: ['dns', 'ip'], allowed_ips: ['192.168.0.0/16'] }))
      expect(outside.status).toBe(400)
      expect(outside.body.error.code).toBe('template_outside_name_constraints')
      expect(outside.body.error.details.problems).toEqual([
        { rule: 'other.test', type: 'dns', reason: 'not_permitted' },
        { rule: '192.168.0.0/16', type: 'ip', reason: 'not_permitted' },
      ])
      const excluded = await w.admin.rpc('templates.update', { id: w.template.id, allowed_dns: ['*.secret.example.test'] })
      expect(excluded.body.error).toMatchObject({ code: 'template_outside_name_constraints', details: { problems: [{ rule: '*.secret.example.test', reason: 'excluded' }] } })
      expect((await w.admin.rpc('templates.get', { id: w.template.id })).body.data.allowed_dns).toEqual(['**.example.test'])
    })

    it('refuses patterns that are not domain patterns or CIDRs, and settings that do not fit together', async () => {
      const w = await world()
      const code = async (overrides: object) => (await w.admin.rpc('templates.create', templateBody(w.issuing.id, 'bad', overrides))).body.error?.code
      expect(await code({ allowed_dns: ['a.*.example.test'] })).toBe('invalid_domain_pattern')
      expect(await code({ allowed_dns: ['^.*\\.example\\.test$'] })).toBe('invalid_domain_pattern')
      expect(await code({ allowed_san_types: ['dns', 'ip'], allowed_ips: ['10.0.0.1/8'] })).toBe('invalid_cidr')
      expect(await code({ allowed_san_types: ['dns', 'ip'], allowed_ips: [] })).toBe('allowed_ips_required')
      expect(await code({ allowed_dns: [] })).toBe('allowed_dns_required')
      expect(await code({ default_ttl_seconds: 400 * 86400 })).toBe('invalid_ttl')
      expect(await code({ extended_key_usages: [] })).toBe('invalid_extended_key_usages')
      expect(await code({ extended_key_usages: ['client_auth', 'client_auth'] })).toBe('invalid_extended_key_usages')
      // Any non-empty set of the supported usages is fine; nothing ties a template to server or client use.
      expect((await w.admin.rpc('templates.create', templateBody(w.issuing.id, 'client-only', { extended_key_usages: ['client_auth'] }))).body.data).toMatchObject({ usage_hint: 'client', extended_key_usages: ['client_auth'] })
      expect(await code({ key_usages: ['key_encipherment'] })).toBe('invalid_key_usages')
      expect(await code({ subject_defaults: { CN: 'fixed' } })).toBe('invalid_subject_defaults')
      expect(await code({ slug: 'Not A Slug' })).toBe('invalid_slug')
      expect(await code({ slug: 'web' })).toBe('template_slug_taken')
    })

    it('refuses a CA that is disabled or has no certificate yet', async () => {
      const w = await world()
      const pending = await ok(w.admin, 'certificate_authorities.create', {
        signing: 'external',
        name: 'Pending',
        slug: 'pending',
        subject: subject('Pending'),
        path_length: 0,
        name_constraints: { permitted: { ...none, dns: ['example.test'] }, excluded: none },
      })
      expect((await w.admin.rpc('templates.create', templateBody(pending.id, 'p'))).body.error.code).toBe('ca_not_active')
      await ok(w.admin, 'certificate_authorities.archive', { id: w.issuing.id })
      const disabled = await w.admin.rpc('templates.create', templateBody(w.issuing.id, 'd'))
      expect(disabled).toMatchObject({ status: 409, body: { error: { code: 'ca_disabled' } } })
      expect((await w.admin.rpc('templates.update', { id: w.template.id, name: 'x' })).body.error.code).toBe('ca_disabled')
      expect((await w.admin.rpc('templates.get', { id: w.template.id })).body.data.permissions.issue).toBe(false)
    })

    it('allows binding to a root but flags it, and notes when the CA ends before the maximum lifetime', async () => {
      const w = await world()
      const onRoot = await ok(w.admin, 'templates.create', templateBody(w.root.id, 'on-root', { allowed_dns: ['anything.test'] }))
      expect(onRoot).toMatchObject({ bound_to_root: true, max_ttl_exceeds_ca: false })
      // The issuing CA lives 365 days; the preset allows 397.
      expect(w.template).toMatchObject({ max_ttl_seconds: 397 * 86400, max_ttl_exceeds_ca: true })
      expect(w.template.ca_remaining_seconds).toBeLessThanOrEqual(365 * 86400)
    })
  })
})
