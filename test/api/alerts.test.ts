import { createHmac, timingSafeEqual } from 'node:crypto'
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { deliverAlert, scanExpiryAlerts } from '@certifly/core/alerts'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, coreContext, query, resetState, sentMails, serverOptions, setupAdmin, waitFor, waitForMail } from '../helpers'

const none = { dns: [], ip: [], email: [] }
const DAY = 86400
const keygen = { algorithm: 'ecdsa-p256', format: 'pem' }

async function ok(client: Client, method: string, body: object) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

interface Received {
  path: string
  headers: IncomingHttpHeaders
  body: string
}

/** A webhook receiver: `/ok` answers 204, `/fail` answers 500 with a short message. */
function receiver() {
  const received: Received[] = []
  let server: Server
  let base = ''
  return {
    received,
    url: (path: string) => `${base}${path}`,
    async start() {
      server = createServer((req, res) => {
        const chunks: Buffer[] = []
        req.on('data', (chunk) => chunks.push(chunk))
        req.on('end', () => {
          received.push({ path: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks).toString('utf8') })
          if (req.url === '/fail') {
            res.writeHead(500, { 'content-type': 'text/plain' })
            res.end('receiver is down')
          } else {
            res.writeHead(204)
            res.end()
          }
        })
      })
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
    },
    stop: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

/** A root, an issuing CA, a server template, and an admin (with an API key), operator and viewer. */
async function world() {
  const admin = await setupAdmin()
  const operator = await addUser(admin, 'op@example.com', 'operator')
  const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
  const adminKey = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
  const root = await ok(admin, 'certificate_authorities.create', { signing: 'self_signed', name: 'Root', slug: 'root', subject: [{ type: 'CN', value: 'Alert Root' }], validity_days: 3650, path_length: 1 })
  const issuing = await ok(admin, 'certificate_authorities.create', {
    signing: 'internal',
    parent_ca_id: root.id,
    name: 'Issuing',
    slug: 'issuing',
    subject: [{ type: 'CN', value: 'Alert Issuing CA' }],
    validity_days: 365,
    path_length: 0,
    name_constraints: { permitted: { ...none, dns: ['example.test'] }, excluded: none },
  })
  const web = await ok(admin, 'templates.create', { preset: 'webserver_tls', name: 'Web', slug: 'web', ca_id: issuing.id, allowed_dns: ['**.example.test'], max_ttl_seconds: 90 * DAY, default_ttl_seconds: 30 * DAY })
  const issue = async (name: string, ttl_seconds = 30 * DAY) =>
    (await ok(operator, 'certificates.issue', { template_id: web.id, keygen, sans: [{ type: 'dns', value: name }], ttl_seconds })).certificate as { id: string; serial: string }
  return { admin, operator, viewer, adminKey, root, issuing, web, issue }
}

const deliveries = (where = '') => query().unsafe(`select * from alert_deliveries ${where} order by created_at`)

describe('alerts', async () => {
  await setup(serverOptions)
  const hooks = receiver()
  beforeAll(() => hooks.start())
  afterAll(() => hooks.stop())
  beforeEach(async () => {
    await resetState()
    hooks.received.length = 0
  })

  it('lets only an admin with a fresh session manage alerts, and operators read the history', async () => {
    const w = await world()
    const channel = { kind: 'email', name: 'Team', recipients: ['team@example.com'] }
    for (const client of [w.operator, w.viewer]) {
      expect((await client.rpc('alert_channels.create', channel)).status).toBe(403)
      expect((await client.rpc('alert_channels.list')).status).toBe(403)
      expect((await client.rpc('alert_rules.list')).status).toBe(403)
    }
    expect((await new Client().rpcWithKey(w.adminKey, 'alert_channels.create', channel)).status).toBe(403)
    expect((await w.operator.rpc('alert_deliveries.list')).status).toBe(200)
    expect((await w.viewer.rpc('alert_deliveries.list')).status).toBe(403)

    const created = await ok(w.admin, 'alert_channels.create', channel)
    expect(created).toMatchObject({ secret: null, channel: { kind: 'email', recipients: ['team@example.com'], has_secret: false } })
    const rule = { name: 'Expiry', event: 'expiring', days_before: [30, 7, 1], channel_ids: [created.channel.id] }
    expect((await w.operator.rpc('alert_rules.create', rule)).status).toBe(403)
    expect((await new Client().rpcWithKey(w.adminKey, 'alert_rules.create', rule)).status).toBe(403)
    expect((await w.admin.rpc('alert_rules.create', { ...rule, days_before: [] })).body.error.code).toBe('thresholds_required')
    expect((await w.admin.rpc('alert_channels.create', { kind: 'webhook', name: 'x', url: 'ftp://example.test/' })).body.error.code).toBe('invalid_url')
    const savedRule = await ok(w.admin, 'alert_rules.create', rule)
    expect(savedRule).toMatchObject({ event: 'expiring', days_before: [30, 7, 1], include_imported: false, enabled: true })

    await ageSessions(30)
    for (const [method, body] of [
      ['alert_rules.update', { id: savedRule.id, enabled: false }],
      ['alert_channels.delete', { id: created.channel.id }],
      ['alert_channel_tests.create', { channel_id: created.channel.id }],
    ] as const) {
      expect((await w.admin.rpc(method, body)).body.error.code).toBe('reauth_required')
    }
  })

  it('signs webhook calls with the secret shown once, which is stored only encrypted', async () => {
    const w = await world()
    const created = await ok(w.admin, 'alert_channels.create', { kind: 'webhook', name: 'Hook', url: hooks.url('/ok') })
    const secret = created.secret as string
    expect(secret).toMatch(/^whsec_/)
    expect(created.channel).toMatchObject({ has_secret: true, url: hooks.url('/ok') })
    await ok(w.admin, 'alert_rules.create', { name: 'Issued', event: 'issued', channel_ids: [created.channel.id] })

    const before = Math.floor(Date.now() / 1000)
    const cert = await w.issue('hooked.example.test')
    const call = await waitFor(async () => hooks.received.find((r) => r.path === '/ok'), 'the webhook call')
    const expected = createHmac('sha256', secret).update(call.body).digest('hex')
    const signature = String(call.headers['x-certifly-signature'])
    expect(signature).toBe(`sha256=${expected}`)
    expect(timingSafeEqual(Buffer.from(signature), Buffer.from(`sha256=${expected}`))).toBe(true)
    const body = JSON.parse(call.body)
    const timestamp = Number(call.headers['x-certifly-timestamp'])
    expect(body.timestamp).toBe(timestamp)
    expect(timestamp).toBeGreaterThanOrEqual(before - 1)
    expect(timestamp).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 1)
    expect(call.headers['content-type']).toBe('application/json')
    expect(call.headers['x-certifly-event']).toBe('issued')
    expect(body).toMatchObject({ event: 'issued', test: false, data: { certificate: { id: cert.id, serial: cert.serial, common_name: null } } })
    expect(call.headers['x-certifly-delivery']).toBe(body.id)

    const history = await waitFor(async () => {
      const res = await w.operator.rpc('alert_deliveries.list')
      return res.body.data[0]?.status === 'sent' ? res.body.data : null
    }, 'the delivery to be marked sent')
    expect(history[0]).toMatchObject({ event: 'issued', status: 'sent', attempts: 1, last_error: null, subject_label: 'hooked.example.test', channel: { name: 'Hook', kind: 'webhook' } })

    // A test through the same channel arrives signed as well.
    const tested = await ok(w.admin, 'alert_channel_tests.create', { channel_id: created.channel.id })
    expect(tested).toMatchObject({ status: 'sent', test: true, attempts: 1 })
    const test = hooks.received.find((r) => JSON.parse(r.body).test === true)!
    expect(test.headers['x-certifly-signature']).toBe(`sha256=${createHmac('sha256', secret).update(test.body).digest('hex')}`)

    // Rotating gives a new secret, once; later calls use it.
    const rotated = await ok(w.admin, 'alert_channels.update', { id: created.channel.id, rotate_secret: true })
    expect(rotated.secret).toMatch(/^whsec_/)
    expect(rotated.secret).not.toBe(secret)

    // Neither secret appears in any answer, the audit log, the job queue or any other table.
    const listed = JSON.stringify((await w.admin.rpc('alert_channels.list')).body)
    expect(listed).toContain('"has_secret":true')
    for (const value of [secret, rotated.secret]) {
      expect(listed).not.toContain(value)
      const tables = await query()`select tablename from pg_tables where schemaname = 'public'`
      for (const { tablename } of tables) {
        const [{ n }] = await query().unsafe(`select count(*)::int as n from "${tablename}" t where t::text like $1`, [`%${value}%`])
        expect(n, `${tablename} holds the secret`).toBe(0)
      }
      const [{ n }] = await query()`select count(*)::int as n from pgboss.job j where j::text like ${`%${value}%`}`
      expect(n).toBe(0)
    }
    const [stored] = await query()`select config from alert_channels`
    expect(stored!.config.secret_enc).toMatch(/^v1\./)
    const events = await query()`select name, data from events where name like 'alert_channels.%' order by created_at`
    expect(events.map((e) => e.name)).toEqual(['alert_channels.create', 'alert_channels.test', 'alert_channels.update'])
    expect(events[2]!.data).toMatchObject({ secret_rotated: true })
  })

  it('mails revocation alerts through the outbox', async () => {
    const w = await world()
    const channel = await ok(w.admin, 'alert_channels.create', { kind: 'email', name: 'Security', recipients: ['security@example.com'] })
    await ok(w.admin, 'alert_rules.create', { name: 'Revoked', event: 'revoked', channel_ids: [channel.channel.id], ca_ids: [w.issuing.id] })
    const cert = await w.issue('mailed.example.test')
    await ok(w.operator, 'certificates.revoke', { id: cert.id, reason: 'key_compromise' })
    const mail = await waitForMail('security@example.com', (m) => m.subject.includes('revoked'))
    expect(mail.subject).toBe('[certifly] Certificate mailed.example.test revoked')
    expect(mail.text).toContain('Reason: key_compromise')
    expect(mail.text).toContain(`/certificates/${cert.id}`)
    await waitFor(async () => (await deliveries())[0]?.status === 'sent', 'the delivery to be marked sent')
  })

  it('sends each expiry threshold once, however often the scan runs', async () => {
    const w = await world()
    const channel = await ok(w.admin, 'alert_channels.create', { kind: 'email', name: 'Ops', recipients: ['ops@example.com'] })
    await ok(w.admin, 'alert_rules.create', { name: 'Expiry', event: 'expiring', days_before: [30, 7, 1], channel_ids: [channel.channel.id] })
    const soon = await w.issue('soon.example.test', 5 * DAY)
    const later = await w.issue('later.example.test', 20 * DAY)
    await w.issue('far.example.test', 60 * DAY)

    const core = await coreContext()
    try {
      const now = new Date()
      expect(await scanExpiryAlerts(core.ctx, now)).toEqual({ queued: 2 })
      expect(await scanExpiryAlerts(core.ctx, now)).toEqual({ queued: 0 })
      const first = await deliveries()
      expect(first.map((d) => [d.subject_id, d.payload.threshold_days]).sort()).toEqual(
        [
          [soon.id, 7],
          [later.id, 30],
        ].sort(),
      )
      // Four and a half days on, the soon one has crossed the last threshold; the later one has not crossed another.
      const on = new Date(now.getTime() + 4.5 * DAY * 1000)
      expect(await scanExpiryAlerts(core.ctx, on)).toEqual({ queued: 1 })
      expect(await scanExpiryAlerts(core.ctx, on)).toEqual({ queued: 0 })
      const all = await deliveries()
      expect(all.map((d) => d.payload.threshold_days)).toContain(1)
      expect(new Set(all.map((d) => d.dedupe_key)).size).toBe(3)
      // Each one is sent by the deliver job.
      for (const job of core.jobs.filter((j) => j.name === 'alerts.deliver')) await deliverAlert(core.ctx, (job.data as { delivery_id: string }).delivery_id)
      expect((await deliveries()).every((d) => d.status === 'sent')).toBe(true)
    } finally {
      await core.close()
    }
    const mails = await sentMails('ops@example.com')
    expect(mails.map((m) => m.subject).sort()).toEqual(
      ['[certifly] Certificate later.example.test expires in 20 days', '[certifly] Certificate soon.example.test expires in 1 day', '[certifly] Certificate soon.example.test expires in 5 days'].sort(),
    )
  })

  it('retries a failing webhook with pg-boss and records the error', async () => {
    const w = await world()
    const channel = await ok(w.admin, 'alert_channels.create', { kind: 'webhook', name: 'Broken', url: hooks.url('/fail') })
    await ok(w.admin, 'alert_rules.create', { name: 'Issued', event: 'issued', channel_ids: [channel.channel.id] })
    await w.issue('retry.example.test')

    const first = await waitFor(async () => {
      const [row] = await deliveries()
      return row?.attempts === 1 && row.status === 'retrying' ? row : null
    }, 'the first failed attempt')
    expect(first.last_error).toBe('HTTP 500: receiver is down')
    const [job] = await query()`select state, retry_count from pgboss.job where name = 'alerts.deliver'`
    expect(job).toMatchObject({ state: 'retry' })

    // Skip the backoff delay instead of waiting a minute; the worker takes the job again.
    await query()`update pgboss.job set start_after = now() where name = 'alerts.deliver' and state = 'retry'`
    const second = await waitFor(async () => {
      const [row] = await deliveries()
      return row?.attempts === 2 ? row : null
    }, 'the retry', 20_000)
    expect(second).toMatchObject({ status: 'retrying', last_error: 'HTTP 500: receiver is down' })
    expect(hooks.received.filter((r) => r.path === '/fail').length).toBeGreaterThanOrEqual(2)

    // A test through a failing channel fails at once and is not retried.
    const tested = await ok(w.admin, 'alert_channel_tests.create', { channel_id: channel.channel.id })
    expect(tested).toMatchObject({ status: 'failed', attempts: 1, last_error: 'HTTP 500: receiver is down' })
    const history = (await w.operator.rpc('alert_deliveries.list', { status: 'failed' })).body.data
    expect(history).toHaveLength(1)
  })
})
