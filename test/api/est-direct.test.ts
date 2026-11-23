import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { setup } from '@nuxt/test-utils/e2e'
import { query, resetState, serverOptions } from '../helpers'
import { basic, certificatesOf, est, estWorld, hasOpenssl, makeRequest, ok, scratch, traefikHeader } from '../support/est'

describe.skipIf(!hasOpenssl)('EST without a proxy secret', async () => {
  await setup(serverOptions)
  beforeEach(resetState)
  const tmp = scratch()
  afterAll(tmp.cleanup)

  it('ignores the forwarded client certificate header, so re-enrollment is refused', async () => {
    // Neither TRUST_PROXY nor EST_PROXY_SECRET is set; sending a secret header changes nothing.
    const w = await estWorld()
    const credential = await ok(w.admin, 'est_credentials.create', { template_id: w.devices.id, name: 'fleet' })
    const csr = makeRequest(tmp, 'dev1.example.test')
    const enrolled = await est('devices', 'simpleenroll', { auth: basic(credential.username, credential.password), body: csr })
    expect(enrolled.status).toBe(200)
    const pem = certificatesOf(tmp, await enrolled.text())[0]!

    const response = await est('devices', 'simplereenroll', { body: csr, headers: { 'x-forwarded-tls-client-cert': traefikHeader(pem), 'x-certifly-proxy-secret': 'proxy-secret-for-tests-0123456789abcdef' } })
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe('Basic realm="certifly EST"')
    expect(await query()`select 1 from certificates where status = 'superseded'`).toHaveLength(0)
  })
})
