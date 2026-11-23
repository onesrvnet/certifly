import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { setup } from '@nuxt/test-utils/e2e'
import { Client, query, resetState, serverOptions } from '../helpers'
import { basic, certificatesOf, est, estWorld, hasOpenssl, makeRequest, ok, scratch, traefikHeader } from '../support/est'

describe.skipIf(!hasOpenssl)('EST behind a proxy without a secret', async () => {
  await setup({ ...serverOptions, env: { TRUST_PROXY: 'true' } })
  beforeEach(resetState)
  const tmp = scratch()
  afterAll(tmp.cleanup)

  it('keeps re-enrollment off while EST_PROXY_SECRET is unset', async () => {
    const w = await estWorld()
    const credential = await ok(w.admin, 'est_credentials.create', { template_id: w.devices.id, name: 'fleet' })
    const csr = makeRequest(tmp, 'dev1.example.test')
    const pem = certificatesOf(tmp, await (await est('devices', 'simpleenroll', { auth: basic(credential.username, credential.password), body: csr })).text())[0]!
    const response = await est('devices', 'simplereenroll', { body: csr, headers: { 'x-forwarded-tls-client-cert': traefikHeader(pem) } })
    expect(response.status).toBe(401)
    expect(await query()`select 1 from certificates where status = 'superseded'`).toHaveLength(0)
  })

  it('takes the client address from the last X-Forwarded-For entry, the one the proxy added', async () => {
    const start = (forwarded: string) =>
      new Client().rpc('cli_logins.start', { code_challenge: 'a'.repeat(43), machine: { hostname: 'box', os: 'linux' } }, { 'x-forwarded-for': forwarded })
    expect((await start('6.6.6.6, 203.0.113.7')).status).toBe(200)
    expect((await start('198.51.100.9')).status).toBe(200)
    const rows = await query()`select ip from cli_logins order by created_at`
    expect(rows.map((r) => r.ip)).toEqual(['203.0.113.7', '198.51.100.9'])
  })
})
