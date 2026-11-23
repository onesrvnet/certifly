import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { setup } from '@nuxt/test-utils/e2e'
import { addUser, ageSessions, Client, query, resetState, serverOptions } from '../helpers'
import { basic, certificatesOf, est, estWorld, hasOpenssl, makeRequest, ok, scratch, traefikHeader } from '../support/est'

if (!hasOpenssl) console.warn('EST tests: the openssl CLI is not installed, so they are skipped')

const PROXY_HEADER = 'x-forwarded-tls-client-cert'
const SECRET = 'proxy-secret-for-tests-0123456789abcdef'
const SECRET_HEADER = 'x-certifly-proxy-secret'
const proxied = (certificate: string, secret = SECRET) => ({ [PROXY_HEADER]: certificate, [SECRET_HEADER]: secret })

async function credential(w: Awaited<ReturnType<typeof estWorld>>, template: { id: string }, name = 'fleet') {
  return (await ok(w.admin, 'est_credentials.create', { template_id: template.id, name })) as { id: string; username: string; password: string }
}

describe.skipIf(!hasOpenssl)('EST', async () => {
  // Behind a proxy that sends its secret, so the forwarded client certificate is honoured.
  await setup({ ...serverOptions, env: { TRUST_PROXY: 'true', EST_PROXY_SECRET: SECRET } })
  beforeEach(resetState)
  const tmp = scratch()
  afterAll(tmp.cleanup)

  it('serves the CA chain without authentication, as base64 certs-only PKCS#7', async () => {
    const w = await estWorld()
    const response = await est('devices', 'cacerts')
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/pkcs7-mime')
    expect(response.headers.get('content-transfer-encoding')).toBe('base64')
    const certs = certificatesOf(tmp, await response.text())
    expect(certs).toEqual([w.issuing.active_certificate.pem, w.root.active_certificate.pem])
    // csrattrs: nothing to ask for.
    expect((await est('devices', 'csrattrs')).status).toBe(204)
  })

  it('answers 404 on every EST path unless the template is active and allows EST', async () => {
    const w = await estWorld()
    for (const [action, init] of [['cacerts', {}], ['csrattrs', {}], ['simpleenroll', { body: 'x' }], ['simplereenroll', { body: 'x' }]] as const) {
      expect((await est('plain', action, init)).status, `plain ${action}`).toBe(404)
      expect((await est('nothing-here', action, init)).status, `missing ${action}`).toBe(404)
    }
    expect((await est('Bad_Slug', 'cacerts')).status).toBe(404)
    // Switching EST off, or archiving the template, closes it again.
    expect((await est('printers', 'cacerts')).status).toBe(200)
    await ok(w.admin, 'templates.update', { id: w.printers.id, allow_est: false })
    expect((await est('printers', 'cacerts')).status).toBe(404)
    expect((await est('devices', 'cacerts')).status).toBe(200)
    await ok(w.admin, 'templates.archive', { id: w.devices.id })
    expect((await est('devices', 'cacerts')).status).toBe(404)
  })

  it('creates credentials for admins with a fresh session, shows the password once, and revokes them', async () => {
    const w = await estWorld()
    const operator = await addUser(w.admin, 'op@example.com', 'operator')
    const viewer = await addUser(w.admin, 'viewer@example.com', 'viewer')
    const body = { template_id: w.devices.id, name: 'Fleet A' }
    expect((await viewer.rpc('est_credentials.create', body)).status).toBe(403)
    expect((await operator.rpc('est_credentials.create', body)).status).toBe(403)
    expect((await new Client().rpcWithKey(w.adminKey, 'est_credentials.create', body)).status).toBe(403)
    await ageSessions(30)
    expect((await w.admin.rpc('est_credentials.create', body)).body.error.code).toBe('reauth_required')

    // The session was aged for this test only; sign in afresh.
    await query()`update sessions set reauth_at = now()`
    const created = (await w.admin.rpc('est_credentials.create', body)).body.data
    expect(created).toMatchObject({ template_id: w.devices.id, name: 'Fleet A', last_used_at: null, revoked_at: null, permissions: { revoke: true } })
    expect(created.username).toMatch(/^est_[\w-]{8}$/)
    // 24 random bytes, base64url.
    expect(created.password).toMatch(/^[\w-]{32}$/)
    const rows = await query()`select password_hash from est_credentials`
    expect(rows[0]!.password_hash).not.toContain(created.password)

    // Listed without the password, for everyone who can read the template.
    for (const client of [w.admin, operator, viewer]) {
      const listed = (await client.rpc('est_credentials.list', { template_id: w.devices.id })).body.data
      expect(listed).toHaveLength(1)
      expect(listed[0].password).toBeUndefined()
      expect(JSON.stringify(listed)).not.toContain(created.password)
    }
    expect((await viewer.rpc('est_credentials.list', { template_id: crypto.randomUUID() })).status).toBe(404)
    expect((await viewer.rpc('est_credentials.list', { template_id: w.printers.id })).body.data).toEqual([])
    expect((await w.admin.rpc('templates.get', { id: w.devices.id })).body.data.est_base_url).toBe(`${process.env.URL}/.well-known/est/devices`)
    expect((await w.admin.rpc('templates.get', { id: w.plain.id })).body.data.est_base_url).toBeNull()

    expect((await operator.rpc('est_credentials.revoke', { id: created.id })).status).toBe(403)
    expect((await w.admin.rpc('est_credentials.revoke', { id: crypto.randomUUID() })).status).toBe(404)
    const revoked = (await w.admin.rpc('est_credentials.revoke', { id: created.id })).body.data
    expect(revoked.revoked_at).not.toBeNull()
    expect(revoked.permissions.revoke).toBe(false)
    // A second revoke changes nothing and writes no second event.
    expect((await w.admin.rpc('est_credentials.revoke', { id: created.id })).body.data.revoked_at).toBe(revoked.revoked_at)

    const events = await query()`select name, data from events where name like 'est_credentials.%' order by created_at`
    expect(events.map((e) => e.name)).toEqual(['est_credentials.create', 'est_credentials.revoke'])
    expect(JSON.stringify(events)).not.toContain(created.password)
  })

  it('enrolls with a credential of the template: the template rules, source est, default tags', async () => {
    const w = await estWorld()
    const mine = await credential(w, w.devices)
    const theirs = await credential(w, w.printers, 'printers')
    const csr = makeRequest(tmp, 'dev1.example.test')

    const noAuth = await est('devices', 'simpleenroll', { body: csr })
    expect(noAuth.status).toBe(401)
    expect(noAuth.headers.get('www-authenticate')).toBe('Basic realm="certifly EST"')
    const wrong = [basic(mine.username, 'wrong-password'), basic('est_unknown', mine.password), basic(theirs.username, theirs.password), 'Basic !!!', 'Bearer abc']
    for (const auth of wrong) {
      const refused = await est('devices', 'simpleenroll', { auth, body: csr })
      expect(refused.status, auth).toBe(401)
      expect(refused.headers.get('www-authenticate')).toBe('Basic realm="certifly EST"')
    }
    expect(await query()`select 1 from certificates where source = 'est'`).toHaveLength(0)
    expect((await query()`select last_used_at from est_credentials where id = ${mine.id}`)[0]!.last_used_at).toBeNull()

    const response = await est('devices', 'simpleenroll', { auth: basic(mine.username, mine.password), body: csr })
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/pkcs7-mime; smime-type=certs-only')
    expect(response.headers.get('content-transfer-encoding')).toBe('base64')
    const [leaf, ...rest] = certificatesOf(tmp, await response.text())
    expect(rest).toEqual([])
    tmp.write('issuer.pem', w.issuing.active_certificate.pem + w.root.active_certificate.pem)
    tmp.write('leaf.pem', leaf!)
    expect(tmp.run(['verify', '-CAfile', 'issuer.pem', 'leaf.pem'])).toContain('leaf.pem: OK')
    expect(tmp.run(['x509', '-in', 'leaf.pem', '-noout', '-ext', 'subjectAltName'])).toContain('DNS:dev1.example.test')

    const listed = (await w.admin.rpc('certificates.list', { source: 'est' })).body.data
    expect(listed).toHaveLength(1)
    expect(listed[0]).toMatchObject({ source: 'est', status: 'active', common_name: 'dev1.example.test', template: { slug: 'devices' } })
    expect(listed[0].tags.map((t: { id: string }) => t.id)).toEqual([w.tag.id])
    // Requested by the protocol client, not by a person.
    expect(listed[0]).toMatchObject({ requested_by_user_id: null, requested_by_api_key_id: null })

    expect((await query()`select last_used_at from est_credentials where id = ${mine.id}`)[0]!.last_used_at).not.toBeNull()
    const [event] = await query()`select actor_type, actor_id, data from events where name = 'certificates.issue'`
    expect(event).toMatchObject({ actor_type: 'est', actor_id: mine.id })
    expect(JSON.stringify(event)).not.toContain(mine.password)

    // Tolerates PEM, raw lines and surrounding whitespace in the request.
    const pem = `-----BEGIN CERTIFICATE REQUEST-----\n${makeRequest(tmp, 'dev2.example.test')}-----END CERTIFICATE REQUEST-----\n`
    expect((await est('devices', 'simpleenroll', { auth: basic(mine.username, mine.password), body: pem })).status).toBe(200)
    expect((await est('devices', 'simpleenroll', { auth: basic(mine.username, mine.password), body: `\n ${makeRequest(tmp, 'dev3.example.test')}\n` })).status).toBe(200)
  })

  it('refuses names the template does not allow and malformed requests with a short text answer', async () => {
    const w = await estWorld()
    const mine = await credential(w, w.devices)
    const auth = basic(mine.username, mine.password)
    const outside = await est('devices', 'simpleenroll', { auth, body: makeRequest(tmp, 'evil.other.test', { sans: 'DNS:evil.other.test' }) })
    expect(outside.status).toBe(400)
    expect(outside.headers.get('content-type')).toContain('text/plain')
    expect(await outside.text()).toMatch(/evil\.other\.test/)
    const sneaky = await est('devices', 'simpleenroll', { auth, body: makeRequest(tmp, 'ok.example.test', { sans: 'DNS:ok.example.test,DNS:evil.other.test' }) })
    expect(sneaky.status).toBe(400)
    expect((await est('devices', 'simpleenroll', { auth, body: 'bm90IGEgcmVxdWVzdA==' })).status).toBe(400)
    expect((await est('devices', 'simpleenroll', { auth, body: '' })).status).toBe(400)
    expect((await est('devices', 'simpleenroll', { auth, body: 'A'.repeat(200_000) })).status).toBe(413)
    expect(await query()`select 1 from certificates where source = 'est'`).toHaveLength(0)

    // A revoked credential stops working at once.
    await ok(w.admin, 'est_credentials.revoke', { id: mine.id })
    expect((await est('devices', 'simpleenroll', { auth, body: makeRequest(tmp, 'late.example.test') })).status).toBe(401)
  })

  it('re-enrolls with the current certificate from the proxy header, and supersedes it', async () => {
    const w = await estWorld()
    const mine = await credential(w, w.devices)
    const theirs = await credential(w, w.printers, 'printers')
    const enroll = async (slug: string, c: { username: string; password: string }, name: string) => {
      const csr = makeRequest(tmp, name)
      const response = await est(slug, 'simpleenroll', { auth: basic(c.username, c.password), body: csr })
      expect(response.status).toBe(200)
      return { csr, pem: certificatesOf(tmp, await response.text())[0]! }
    }
    const first = await enroll('devices', mine, 'dev1.example.test')
    const foreign = await enroll('printers', theirs, 'prn1.example.test')
    const state = async () => query()`select status, superseded_by_id, source, id from certificates order by created_at`

    // Without the header, with a garbled one, or with a certificate of another template or none of ours.
    expect((await est('devices', 'simplereenroll', { body: first.csr })).status).toBe(401)
    const noAuth = await est('devices', 'simplereenroll', { body: first.csr, headers: proxied('!!!') })
    expect(noAuth.status).toBe(401)
    expect(noAuth.headers.get('www-authenticate')).toBe('Basic realm="certifly EST"')
    expect((await est('devices', 'simplereenroll', { body: first.csr, headers: proxied(traefikHeader(foreign.pem)) })).status).toBe(403)
    expect((await est('devices', 'simplereenroll', { body: first.csr, headers: proxied(traefikHeader(w.issuing.active_certificate.pem)) })).status).toBe(403)
    // Basic credentials do not re-enroll.
    expect((await est('devices', 'simplereenroll', { body: first.csr, auth: basic(mine.username, mine.password) })).status).toBe(401)
    expect(await state()).toHaveLength(2)

    // The request must repeat the subject and SANs of the certificate.
    const other = makeRequest(tmp, 'dev9.example.test')
    const mismatch = await est('devices', 'simplereenroll', { body: other, headers: proxied(traefikHeader(first.pem)) })
    expect(mismatch.status).toBe(400)
    expect(await mismatch.text()).toMatch(/same/)
    const extraSan = makeRequest(tmp, 'dev1.example.test', { sans: 'DNS:dev1.example.test,DNS:extra.example.test' })
    expect((await est('devices', 'simplereenroll', { body: extraSan, headers: proxied(traefikHeader(first.pem)) })).status).toBe(400)

    // A new key for the same name is fine.
    const renewedCsr = makeRequest(tmp, 'dev1.example.test')
    const response = await est('devices', 'simplereenroll', { body: renewedCsr, headers: proxied(traefikHeader(first.pem)) })
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/pkcs7-mime; smime-type=certs-only')
    const [renewed] = certificatesOf(tmp, await response.text())
    expect(renewed).not.toBe(first.pem)
    tmp.write('issuer.pem', w.issuing.active_certificate.pem + w.root.active_certificate.pem)
    tmp.write('renewed.pem', renewed!)
    expect(tmp.run(['verify', '-CAfile', 'issuer.pem', 'renewed.pem'])).toContain('renewed.pem: OK')

    const rows = await state()
    expect(rows.map((r) => r.status)).toEqual(['superseded', 'active', 'active'])
    const old = rows.find((r) => r.status === 'superseded')!
    const fresh = rows.find((r) => r.id === old.superseded_by_id)!
    expect(fresh).toMatchObject({ status: 'active', source: 'est' })
    expect((await w.admin.rpc('certificates.list', { source: 'est', status: 'superseded' })).body.data).toHaveLength(1)
    const renewalEvent = (await query()`select actor_type, data from events where name = 'certificates.renew'`)[0]!
    expect(renewalEvent).toMatchObject({ actor_type: 'est', data: { previous_certificate_id: old.id } })
    // The new certificate keeps the tags of the old one.
    expect((await w.admin.rpc('certificates.list', { source: 'est', status: 'active', template_id: w.devices.id })).body.data[0].tags.map((t: { id: string }) => t.id)).toEqual([w.tag.id])

    // The superseded certificate no longer authenticates; the new one does, also as URL-encoded PEM (nginx).
    expect((await est('devices', 'simplereenroll', { body: renewedCsr, headers: proxied(traefikHeader(first.pem)) })).status).toBe(403)
    const again = await est('devices', 'simplereenroll', { body: makeRequest(tmp, 'dev1.example.test'), headers: proxied(encodeURIComponent(renewed!)) })
    expect(again.status).toBe(200)
  })

  it('only reads the client certificate header when the proxy secret matches', async () => {
    const w = await estWorld()
    const mine = await credential(w, w.devices)
    const csr = makeRequest(tmp, 'dev1.example.test')
    const pem = certificatesOf(tmp, await (await est('devices', 'simpleenroll', { auth: basic(mine.username, mine.password), body: csr })).text())[0]!
    const cert = traefikHeader(pem)
    for (const headers of [{ [PROXY_HEADER]: cert }, proxied(cert, 'wrong'), proxied(cert, `${SECRET}x`), proxied(cert, ''), { [SECRET_HEADER]: SECRET }]) {
      const refused = await est('devices', 'simplereenroll', { body: csr, headers })
      expect(refused.status).toBe(401)
      expect(refused.headers.get('www-authenticate')).toBe('Basic realm="certifly EST"')
    }
    expect(await query()`select 1 from certificates where status = 'superseded'`).toHaveLength(0)
    expect((await est('devices', 'simplereenroll', { body: csr, headers: proxied(cert) })).status).toBe(200)
  })

  it('refuses a revoked certificate for re-enrollment', async () => {
    const w = await estWorld()
    const mine = await credential(w, w.devices)
    const csr = makeRequest(tmp, 'dev1.example.test')
    const pem = certificatesOf(tmp, await (await est('devices', 'simpleenroll', { auth: basic(mine.username, mine.password), body: csr })).text())[0]!
    const id = (await query()`select id from certificates where source = 'est'`)[0]!.id as string
    await ok(w.admin, 'certificates.revoke', { id, reason: 'key_compromise' })
    expect((await est('devices', 'simplereenroll', { body: csr, headers: proxied(traefikHeader(pem)) })).status).toBe(403)
  })
})
