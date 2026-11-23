// acme-client first: its x509 needs the full reflect-metadata, which pki's small shim leaves alone only when it is already there.
import acme from 'acme-client'
import { createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, sign } from 'node:crypto'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createSecureContext, createServer as createTlsServer, type SecureContext, type Server as TlsServer } from 'node:tls'
import { cleanupExpired } from '@certifly/core/cleanup'
import { reverseDnsName } from '@certifly/pki'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { addUser, ageSessions, Client, coreContext, query, resetState, serverOptions, setupAdmin } from '../helpers'

const hasOpenssl = spawnSync('openssl', ['version']).status === 0
if (!hasOpenssl) console.warn('acme tests: the openssl CLI is not installed, so the OpenSSL checks are skipped')

const none = { dns: [], ip: [], email: [] }
const DAY = 86400
const URN = 'urn:ietf:params:acme:error:'

async function ok(client: Client, method: string, body: object) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

/** A local port nothing listens on, for the server under test and the challenge servers. */
async function listen(server: HttpServer | TlsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return (server.address() as AddressInfo).port
}

// What the "client machine" serves for the challenges: the answers per path (http-01) and the
// certificates per server name (tls-alpn-01).
const httpAnswers = new Map<string, string>()
const tlsContexts = new Map<string, SecureContext>()
const httpServer = createHttpServer((req, res) => {
  const answer = httpAnswers.get(req.url ?? '')
  if (answer === undefined) {
    res.writeHead(404).end('not here')
    return
  }
  res.writeHead(200, { 'content-type': 'text/plain' }).end(`${answer}\n`)
})
const tlsServer = createTlsServer({ ALPNProtocols: ['acme-tls/1'], SNICallback: (name, done) => done(null, tlsContexts.get(name)) }, (socket) => {
  socket.on('error', () => {})
  socket.end()
})
tlsServer.on('tlsClientError', () => {})

const http01Port = await listen(httpServer)
const tlsAlpn01Port = await listen(tlsServer)
const serverPort = await (async () => {
  const probe = createHttpServer()
  const port = await listen(probe)
  await new Promise((resolve) => probe.close(resolve))
  return port
})()
const origin = `http://127.0.0.1:${serverPort}`

afterAll(async () => {
  await Promise.all([new Promise((resolve) => httpServer.close(resolve)), new Promise((resolve) => tlsServer.close(resolve))])
})

/** A scratch directory for OpenSSL. */
function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-acme-test-'))
  const status = (args: string[]) => {
    const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' })
    return { code: result.status, out: result.stdout + result.stderr }
  }
  const run = (args: string[]) => {
    const result = status(args)
    if (result.code !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.out}`)
    return result.out
  }
  return { run, status, write: (name: string, data: string) => writeFileSync(join(dir, name), data), cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

// ---------------------------------------------------------------------------------------------
// A bare-bones ACME client, to send requests the library never would.

const b64 = (data: string | Buffer) => Buffer.from(data).toString('base64url')

class RawAcme {
  readonly privateKey: KeyObject
  readonly jwk: Record<string, unknown>

  constructor(
    private readonly base: string,
    pem?: string,
  ) {
    this.privateKey = pem ? createPrivateKey(pem) : generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey
    this.jwk = createPublicKey(this.privateKey).export({ format: 'jwk' }) as Record<string, unknown>
  }

  url(path: string) {
    return `${this.base}/${path}`
  }

  async nonce(): Promise<string> {
    return (await fetch(this.url('new-nonce'), { method: 'HEAD' })).headers.get('replay-nonce')!
  }

  /** A signed body. `header` overrides or removes (undefined) protected header members. */
  async body(url: string, payload: unknown, header: Record<string, unknown> = {}) {
    const protectedHeader: Record<string, unknown> = { alg: 'ES256', nonce: await this.nonce(), url, ...header }
    for (const key of Object.keys(protectedHeader)) if (protectedHeader[key] === undefined) delete protectedHeader[key]
    const protected_b64 = b64(JSON.stringify(protectedHeader))
    const payload_b64 = payload === '' ? '' : b64(JSON.stringify(payload))
    const signature = sign('sha256', Buffer.from(`${protected_b64}.${payload_b64}`), { key: this.privateKey, dsaEncoding: 'ieee-p1363' })
    return { protected: protected_b64, payload: payload_b64, signature: b64(signature) }
  }

  async send(url: string, body: unknown, contentType = 'application/jose+json') {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': contentType }, body: JSON.stringify(body) })
    const text = await response.text()
    let json: any = null
    try {
      json = JSON.parse(text)
    } catch {
      // not JSON
    }
    return { status: response.status, headers: response.headers, json, text }
  }

  /** Signed with the account key (`kid`). */
  async post(url: string, payload: unknown, kid: string, header: Record<string, unknown> = {}) {
    return this.send(url, await this.body(url, payload, { kid, ...header }))
  }

  /** Signed with the key in the request (`jwk`). */
  async postWithJwk(url: string, payload: unknown, header: Record<string, unknown> = {}) {
    return this.send(url, await this.body(url, payload, { jwk: this.jwk, ...header }))
  }

  /** An external account binding for this key. */
  binding(kid: string, hmacKey: string, options: { url?: string; jwk?: unknown; alg?: string } = {}) {
    const protected_b64 = b64(JSON.stringify({ alg: options.alg ?? 'HS256', kid, url: options.url ?? this.url('new-account') }))
    const payload_b64 = b64(JSON.stringify(options.jwk ?? this.jwk))
    const signature = createHmac('sha256', Buffer.from(hmacKey, 'base64url')).update(`${protected_b64}.${payload_b64}`).digest()
    return { protected: protected_b64, payload: payload_b64, signature: b64(signature) }
  }
}

// ---------------------------------------------------------------------------------------------

describe('acme', async () => {
  await setup({ ...serverOptions, port: serverPort, env: { PKI_BASE_URL: origin, ACME_HTTP01_PORT: String(http01Port), ACME_TLSALPN01_PORT: String(tlsAlpn01Port) } })
  beforeEach(async () => {
    await resetState()
    httpAnswers.clear()
    tlsContexts.clear()
  })

  /** An admin, an operator and a viewer; a root and an issuing CA; a template with ACME, a default tag, and one without. */
  async function world() {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const viewer = await addUser(admin, 'viewer@example.com', 'viewer')
    const root = await ok(admin, 'certificate_authorities.create', {
      signing: 'self_signed',
      name: 'Root',
      slug: 'root',
      subject: [{ type: 'CN', value: 'ACME Test Root' }],
      validity_days: 3650,
      path_length: 1,
    })
    const issuing = await ok(admin, 'certificate_authorities.create', {
      signing: 'internal',
      parent_ca_id: root.id,
      name: 'Issuing',
      slug: 'issuing',
      subject: [{ type: 'CN', value: 'ACME Test Issuing CA' }],
      validity_days: 365,
      path_length: 0,
      name_constraints: { permitted: { ...none, dns: ['localhost'], ip: ['127.0.0.0/8'] }, excluded: none },
    })
    const tag = await ok(admin, 'tags.create', { name: 'Automated', color: 'teal' })
    const settings = { preset: 'webserver_tls', ca_id: issuing.id, allowed_san_types: ['dns', 'ip'], allowed_dns: ['localhost'], allowed_ips: ['127.0.0.0/8'], max_ttl_seconds: 90 * DAY, default_ttl_seconds: 30 * DAY }
    const web = await ok(admin, 'templates.create', { ...settings, name: 'Web', slug: 'web', allow_acme: true, tag_ids: [tag.id] })
    const other = await ok(admin, 'templates.create', { ...settings, name: 'Other', slug: 'other', allow_acme: true })
    const plain = await ok(admin, 'templates.create', { ...settings, name: 'Plain', slug: 'plain' })
    return { admin, operator, viewer, root, issuing, tag, web, other, plain }
  }
  type World = Awaited<ReturnType<typeof world>>

  const eabKey = (w: World, template = w.web, name = 'laptop') => ok(w.admin, 'acme_eab_keys.create', { template_id: template.id, name }) as Promise<{ id: string; kid: string; hmac_key: string }>

  const directoryUrl = (slug = 'web') => `${origin}/acme/${slug}/directory`

  async function newClient(w: World, options: { rsa?: boolean; slug?: string; template?: World['web'] } = {}) {
    const eab = await eabKey(w, options.template)
    const accountKey = options.rsa ? await acme.crypto.createPrivateKey() : await acme.crypto.createPrivateEcdsaKey()
    const client = new acme.Client({
      directoryUrl: directoryUrl(options.slug),
      accountKey,
      externalAccountBinding: { kid: eab.kid, hmacKey: eab.hmac_key },
      backoffAttempts: 40,
      backoffMin: 100,
      backoffMax: 400,
    })
    await client.createAccount({ termsOfServiceAgreed: true, contact: ['mailto:ops@example.test'] })
    return { client, eab, accountKey: accountKey.toString(), raw: new RawAcme(`${origin}/acme/${options.slug ?? 'web'}`, accountKey.toString()) }
  }
  type Enrolled = Awaited<ReturnType<typeof newClient>>

  /** Serves the answer to one challenge, from the "client machine". */
  async function serve(authz: any, challenge: any, keyAuthorization: string) {
    if (challenge.type === 'http-01') httpAnswers.set(`/.well-known/acme-challenge/${challenge.token}`, keyAuthorization)
    else {
      const [key, cert] = await acme.crypto.createAlpnCertificate(authz, keyAuthorization, await acme.crypto.createPrivateEcdsaKey())
      const name = authz.identifier.type === 'ip' ? reverseDnsName(authz.identifier.value) : authz.identifier.value
      tlsContexts.set(name, createSecureContext({ key: key.toString(), cert: cert.toString() }))
    }
  }

  async function csrFor(names: string[]) {
    const key = await acme.crypto.createPrivateEcdsaKey()
    const [, csr] = await acme.crypto.createCsr({ altNames: names }, key)
    return { key: key.toString(), csr }
  }

  /** The whole flow: order, challenges, finalize, download. (The library's `auto` only orders dns names, so addresses go by hand.) */
  async function enroll(c: Enrolled, names: string[], type: 'http-01' | 'tls-alpn-01') {
    const { key, csr } = await csrFor(names)
    if (names.every((name) => !/^[\d.]+$/.test(name))) {
      const certificate = await c.client.auto({
        csr,
        challengePriority: [type],
        skipChallengeVerification: true,
        termsOfServiceAgreed: true,
        challengeCreateFn: serve,
        challengeRemoveFn: async () => {},
      })
      return { certificate, key }
    }
    const order = await readyOrder(c, names, type)
    const finalized = await c.client.finalizeOrder(order, csr)
    return { certificate: await c.client.getCertificate(finalized), key }
  }

  /** Orders and answers every challenge, but does not finalize. */
  async function readyOrder(c: Enrolled, names: string[], type: 'http-01' | 'tls-alpn-01' = 'http-01') {
    const order = await c.client.createOrder({ identifiers: names.map((value) => ({ type: /^[\d.]+$/.test(value) ? 'ip' : 'dns', value })) })
    for (const authz of await c.client.getAuthorizations(order)) {
      const challenge = authz.challenges.find((ch: any) => ch.type === type)!
      await serve(authz, challenge, await c.client.getChallengeKeyAuthorization(challenge))
      await c.client.completeChallenge(challenge)
      await c.client.waitForValidStatus(challenge)
    }
    return order
  }

  /** The first certificate of a chain. */
  const leafOf = (chain: string) => chain.split(/(?<=-----END CERTIFICATE-----)\s*/)[0]!

  const messageOf = (promise: Promise<unknown>) => promise.then(() => '', (error: Error) => error.message)

  describe('protocol basics', () => {
    it('serves the directory and nonces with the headers RFC 8555 asks for', async () => {
      await world()
      const response = await fetch(directoryUrl())
      expect(response.status).toBe(200)
      expect(response.headers.get('cache-control')).toBe('no-store')
      expect(response.headers.get('replay-nonce')).toBeTruthy()
      expect(response.headers.get('link')).toBe(`<${directoryUrl()}>;rel="index"`)
      expect(await response.json()).toEqual({
        newNonce: `${origin}/acme/web/new-nonce`,
        newAccount: `${origin}/acme/web/new-account`,
        newOrder: `${origin}/acme/web/new-order`,
        revokeCert: `${origin}/acme/web/revoke-cert`,
        meta: { externalAccountRequired: true },
      })

      const head = await fetch(`${origin}/acme/web/new-nonce`, { method: 'HEAD' })
      const get = await fetch(`${origin}/acme/web/new-nonce`)
      expect([head.status, get.status]).toEqual([200, 204])
      const nonces = [head, get].map((r) => r.headers.get('replay-nonce'))
      expect(nonces[0]).toBeTruthy()
      expect(nonces[0]).not.toBe(nonces[1])
      for (const r of [head, get]) {
        expect(r.headers.get('cache-control')).toBe('no-store')
        expect(r.headers.get('link')).toContain('rel="index"')
      }
    })

    it('answers 404 on every path of a template without ACME, an archived one and an unknown one', async () => {
      const w = await world()
      const raw = new RawAcme(`${origin}/acme/plain`)
      const paths = ['directory', 'new-nonce']
      for (const slug of ['plain', 'nothing-here']) {
        for (const path of paths) expect((await fetch(`${origin}/acme/${slug}/${path}`)).status).toBe(404)
        expect((await fetch(`${origin}/acme/${slug}/new-nonce`, { method: 'HEAD' })).status).toBe(404)
        for (const path of ['new-account', 'new-order', 'revoke-cert', `account/${crypto.randomUUID()}`, `order/${crypto.randomUUID()}`, `order/${crypto.randomUUID()}/finalize`, `authz/${crypto.randomUUID()}`, `challenge/${crypto.randomUUID()}`, `cert/${crypto.randomUUID()}`]) {
          const res = await raw.send(`${origin}/acme/${slug}/${path}`, { protected: '', payload: '', signature: '' })
          expect({ path, status: res.status }).toEqual({ path, status: 404 })
          expect(res.headers.get('content-type')).toContain('application/problem+json')
        }
      }
      // An archived template is gone too.
      expect((await w.admin.rpc('templates.archive', { id: w.other.id })).status).toBe(200)
      expect((await fetch(directoryUrl('other'))).status).toBe(404)
      // Turning ACME off hides the directory of a live template.
      expect((await fetch(directoryUrl())).status).toBe(200)
      expect((await w.admin.rpc('templates.update', { id: w.web.id, allow_acme: false })).status).toBe(200)
      expect((await fetch(directoryUrl())).status).toBe(404)
    })

    it('answers errors as problem documents with a fresh nonce, and rejects a replayed nonce', async () => {
      await world()
      const raw = new RawAcme(`${origin}/acme/web`)
      const url = raw.url('new-account')
      const body = await raw.body(url, { onlyReturnExisting: true }, { jwk: raw.jwk })
      const first = await raw.send(url, body)
      expect(first.status).toBe(400)
      expect(first.headers.get('content-type')).toContain('application/problem+json')
      expect(first.json).toMatchObject({ type: `${URN}accountDoesNotExist`, status: 400 })
      expect(first.headers.get('replay-nonce')).toBeTruthy()

      const replay = await raw.send(url, body)
      expect(replay.json).toMatchObject({ type: `${URN}badNonce`, status: 400 })
      expect(replay.headers.get('replay-nonce')).toBeTruthy()
      expect(replay.headers.get('cache-control')).toBe('no-store')

      const stranger = await raw.send(url, await raw.body(url, {}, { jwk: raw.jwk, nonce: 'made-up' }))
      expect(stranger.json.type).toBe(`${URN}badNonce`)

      const missing = await raw.send(url, await raw.body(url, {}, { jwk: raw.jwk, nonce: undefined }))
      expect(missing.json.type).toBe(`${URN}badNonce`)
    })

    it('verifies the envelope: content type, url, jwk or kid, algorithm and signature', async () => {
      const w = await world()
      const raw = new RawAcme(`${origin}/acme/web`)
      const url = raw.url('new-account')
      const type = async (promise: Promise<{ json: any }>) => (await promise).json.type

      expect(await type(raw.send(url, await raw.body(url, {}, { jwk: raw.jwk }), 'application/json'))).toBe(`${URN}malformed`)
      expect(await type(raw.send(url, 'not a jws'))).toBe(`${URN}malformed`)
      expect(await type(raw.postWithJwk(url, {}, { url: raw.url('new-order') }))).toBe(`${URN}unauthorized`)
      expect(await type(raw.postWithJwk(url, {}, { kid: `${origin}/acme/web/account/${crypto.randomUUID()}` }))).toBe(`${URN}malformed`)
      expect(await type(raw.send(url, await raw.body(url, {}, {})))).toBe(`${URN}malformed`)
      const hs = await raw.postWithJwk(url, {}, { alg: 'HS256' })
      expect(hs.json).toMatchObject({ type: `${URN}badSignatureAlgorithm`, algorithms: ['ES256', 'ES384', 'RS256', 'EdDSA'] })
      expect((await raw.postWithJwk(url, {}, { alg: 'none' })).json.type).toBe(`${URN}badSignatureAlgorithm`)
      // A good header with a signature from another key.
      const good = await raw.body(url, {}, { jwk: raw.jwk })
      const other = new RawAcme(`${origin}/acme/web`)
      const forged = { ...good, signature: (await other.body(url, {}, { jwk: raw.jwk })).signature }
      expect(await type(raw.send(url, forged))).toBe(`${URN}malformed`)
      // The account key must be a kid for everything but new-account and revoke-cert.
      expect((await raw.postWithJwk(raw.url('new-order'), { identifiers: [{ type: 'dns', value: 'localhost' }] })).json.type).toBe(`${URN}malformed`)
      expect((await raw.postWithJwk(raw.url('new-account'), { onlyReturnExisting: true }, { jwk: { ...raw.jwk, d: 'secret' } })).json.type).toBe(`${URN}badPublicKey`)
    })

    it('limits ACME requests per client address', async () => {
      // The default limit is high; this only checks that the limiter is in the path by reading its headers.
      await world()
      const response = await fetch(directoryUrl())
      expect(response.headers.get('ratelimit-limit')).toBe('600')
    })
  })

  describe('accounts and external account binding', () => {
    it('requires a binding, and registers an account bound to one of the template’s keys', async () => {
      const w = await world()
      const raw = new RawAcme(`${origin}/acme/web`)
      const url = raw.url('new-account')
      const e = await eabKey(w)

      const without = await raw.postWithJwk(url, { termsOfServiceAgreed: true })
      expect(without).toMatchObject({ status: 403, json: { type: `${URN}externalAccountRequired` } })

      const created = await raw.postWithJwk(url, { contact: ['mailto:a@example.test'], externalAccountBinding: raw.binding(e.kid, e.hmac_key) })
      expect(created.status).toBe(201)
      expect(created.json).toEqual({ status: 'valid', contact: ['mailto:a@example.test'] })
      const location = created.headers.get('location')!
      expect(location).toMatch(new RegExp(`^${origin}/acme/web/account/[0-9a-f-]{36}$`))
      expect(created.headers.get('replay-nonce')).toBeTruthy()

      // The same key again finds the account.
      const again = await raw.postWithJwk(url, { externalAccountBinding: raw.binding(e.kid, e.hmac_key) })
      expect(again.status).toBe(200)
      expect(again.headers.get('location')).toBe(location)
      const existing = await raw.postWithJwk(url, { onlyReturnExisting: true })
      expect(existing.status).toBe(200)
      expect(existing.headers.get('location')).toBe(location)
      expect((await new RawAcme(`${origin}/acme/web`).postWithJwk(url, { onlyReturnExisting: true })).json.type).toBe(`${URN}accountDoesNotExist`)

      const [{ n }] = await query()`select count(*)::int as n from acme_accounts`
      expect(n).toBe(1)
      const [key] = await query()`select last_used_at from acme_eab_keys where id = ${e.id}`
      expect(key!.last_used_at).not.toBeNull()
      const [event] = await query()`select actor_type, actor_id, subject_type, data from events where name = 'acme_accounts.create'`
      expect(event).toMatchObject({ actor_type: 'acme', subject_type: 'acme_account' })
      expect(event!.actor_id).toBe(location.split('/').pop())
      expect(JSON.stringify(event!.data)).not.toContain(e.hmac_key)

      // The template shows its directory and how many accounts it has.
      const template = (await w.admin.rpc('templates.get', { id: w.web.id })).body.data
      expect(template).toMatchObject({ acme_directory_url: directoryUrl(), acme_account_count: 1 })
      expect((await w.admin.rpc('templates.get', { id: w.plain.id })).body.data).toMatchObject({ acme_directory_url: null, acme_account_count: 0 })
    })

    it('refuses wrong, foreign, malformed and revoked bindings', async () => {
      const w = await world()
      const raw = new RawAcme(`${origin}/acme/web`)
      const url = raw.url('new-account')
      const e = await eabKey(w)
      const foreign = await eabKey(w, w.other)
      const register = (externalAccountBinding: unknown) => raw.postWithJwk(url, { externalAccountBinding })

      const wrongKey = await register(raw.binding(e.kid, Buffer.alloc(32, 7).toString('base64url')))
      expect(wrongKey).toMatchObject({ status: 403, json: { type: `${URN}unauthorized` } })
      expect((await register(raw.binding('no-such-kid', e.hmac_key))).json.type).toBe(`${URN}unauthorized`)
      // A key of another template does not bind accounts here.
      expect((await register(raw.binding(foreign.kid, foreign.hmac_key))).json.type).toBe(`${URN}unauthorized`)
      // Bound to another account key, or another url, or signed with a weaker or unknown algorithm.
      expect((await register(raw.binding(e.kid, e.hmac_key, { jwk: new RawAcme(url).jwk }))).json.type).toBe(`${URN}malformed`)
      expect((await register(raw.binding(e.kid, e.hmac_key, { url: raw.url('new-order') }))).json.type).toBe(`${URN}malformed`)
      expect((await register(raw.binding(e.kid, e.hmac_key, { alg: 'ES256' }))).json.type).toBe(`${URN}badSignatureAlgorithm`)
      expect((await register('nope')).json.type).toBe(`${URN}malformed`)

      expect((await w.admin.rpc('acme_eab_keys.revoke', { id: e.id })).status).toBe(200)
      expect((await register(raw.binding(e.kid, e.hmac_key))).json.type).toBe(`${URN}unauthorized`)
      const [{ n }] = await query()`select count(*)::int as n from acme_accounts`
      expect(n).toBe(0)
    })

    it('stops accounts bound to a revoked key, and lets an account change its contact or deactivate itself', async () => {
      const w = await world()
      const c = await newClient(w)
      const accountUrl = c.client.getAccountUrl()
      const orderBody = { identifiers: [{ type: 'dns', value: 'localhost' }] }

      const updated = await c.client.updateAccount({ contact: ['mailto:new@example.test'] })
      expect(updated.contact).toEqual(['mailto:new@example.test'])
      expect((await c.raw.post(accountUrl, { contact: ['https://example.test'] }, accountUrl)).json.type).toBe(`${URN}unsupportedContact`)
      expect((await c.raw.post(accountUrl, { contact: ['mailto:not-an-address'] }, accountUrl)).json.type).toBe(`${URN}invalidContact`)
      // Only the account itself may read or change itself.
      const second = await newClient(w)
      expect((await second.raw.post(accountUrl, {}, second.client.getAccountUrl())).json.type).toBe(`${URN}unauthorized`)
      expect((await c.raw.post(c.raw.url('new-order'), orderBody, accountUrl)).status).toBe(201)

      expect((await w.admin.rpc('acme_eab_keys.revoke', { id: c.eab.id })).status).toBe(200)
      const blocked = await c.raw.post(c.raw.url('new-order'), orderBody, accountUrl)
      expect(blocked).toMatchObject({ status: 403, json: { type: `${URN}unauthorized` } })
      // The other account has its own key and keeps working.
      expect((await second.raw.post(second.raw.url('new-order'), orderBody, second.client.getAccountUrl())).status).toBe(201)

      const deactivated = await second.client.updateAccount({ status: 'deactivated' })
      expect(deactivated.status).toBe('deactivated')
      expect((await second.raw.post(second.raw.url('new-order'), orderBody, second.client.getAccountUrl())).json.type).toBe(`${URN}unauthorized`)
      const names = (await query()`select name from events where name like 'acme_accounts.%' order by created_at`).map((r) => r.name)
      expect(names).toEqual(['acme_accounts.create', 'acme_accounts.update', 'acme_accounts.create', 'acme_accounts.deactivate'])
    })
  })

  describe('orders', () => {
    it('hands out authorizations with both challenge types and checks identifiers against the template', async () => {
      const w = await world()
      const c = await newClient(w)
      const accountUrl = c.client.getAccountUrl()
      const post = (payload: unknown) => c.raw.post(c.raw.url('new-order'), payload, accountUrl)

      const created = await post({ identifiers: [{ type: 'dns', value: 'LocalHost' }, { type: 'ip', value: '127.0.0.1' }, { type: 'dns', value: 'localhost' }] })
      expect(created.status).toBe(201)
      expect(created.json).toMatchObject({ status: 'pending', identifiers: [{ type: 'dns', value: 'localhost' }, { type: 'ip', value: '127.0.0.1' }] })
      expect(created.json.authorizations).toHaveLength(2)
      expect(created.json.finalize).toMatch(/\/order\/[0-9a-f-]{36}\/finalize$/)
      expect(created.headers.get('location')).toMatch(/\/order\/[0-9a-f-]{36}$/)
      expect(new Date(created.json.expires).getTime()).toBeGreaterThan(Date.now() + 6 * DAY * 1000)

      const authz = await c.raw.post(created.json.authorizations[0], '', accountUrl)
      expect(authz.json).toMatchObject({ identifier: { type: 'dns', value: 'localhost' }, status: 'pending' })
      expect(authz.json.challenges.map((ch: any) => ch.type).sort()).toEqual(['http-01', 'tls-alpn-01'])
      for (const ch of authz.json.challenges) {
        expect(ch.token.length).toBeGreaterThanOrEqual(22)
        expect(ch.url).toMatch(/\/challenge\/[0-9a-f-]{36}$/)
      }
      const read = await c.raw.post(created.headers.get('location')!, '', accountUrl)
      expect(read.json).toMatchObject({ status: 'pending' })

      const rejected = async (identifiers: unknown, type: string, status = 403) => {
        const res = await post({ identifiers })
        expect({ identifiers, status: res.status, type: res.json.type }).toEqual({ identifiers, status, type: `${URN}${type}` })
        return res.json
      }
      const outside = await rejected([{ type: 'dns', value: 'localhost' }, { type: 'dns', value: 'evil.example.org' }], 'rejectedIdentifier')
      expect(outside.subproblems).toMatchObject([{ type: `${URN}rejectedIdentifier`, identifier: { type: 'dns', value: 'evil.example.org' } }])
      await rejected([{ type: 'dns', value: '*.localhost' }], 'rejectedIdentifier')
      await rejected([{ type: 'ip', value: '10.0.0.1' }], 'rejectedIdentifier')
      await rejected([{ type: 'dns', value: 'not a name' }], 'rejectedIdentifier', 400)
      await rejected([{ type: 'email', value: 'a@localhost' }], 'unsupportedIdentifier', 400)
      await rejected([], 'malformed', 400)
      await rejected('nope', 'malformed', 400)
      await rejected([{ type: 'dns' }], 'malformed', 400)

      // Another account sees none of this.
      const stranger = await newClient(w)
      expect((await stranger.raw.post(created.headers.get('location')!, '', stranger.client.getAccountUrl())).status).toBe(404)
      expect((await stranger.raw.post(created.json.authorizations[0], '', stranger.client.getAccountUrl())).status).toBe(404)
    })

    it('refuses to finalize an order that is not ready, and a CSR for other names, and keeps the order for another try', async () => {
      const w = await world()
      const c = await newClient(w)

      const pending = await c.client.createOrder({ identifiers: [{ type: 'dns', value: 'localhost' }] })
      const { csr: good } = await csrFor(['localhost'])
      expect(await messageOf(c.client.finalizeOrder(pending, good))).toMatch(/not ready/i)

      const ready = await readyOrder(c, ['localhost'])
      expect((await c.client.getOrder(ready)).status).toBe('ready')
      const { csr: other } = await csrFor(['localhost', '127.0.0.1'])
      expect(await messageOf(c.client.finalizeOrder(ready, other))).toMatch(/exactly the identifiers/i)
      expect((await c.client.getOrder(ready)).status).toBe('ready')

      const finalized = await c.client.finalizeOrder(ready, good)
      expect(finalized.status).toBe('valid')
      expect(finalized.certificate).toMatch(/\/cert\/[0-9a-f-]{36}$/)
      // Finalizing twice is refused.
      expect(await messageOf(c.client.finalizeOrder(ready, good))).toMatch(/not ready/i)
    })

    it('offers an order cut off while finalizing for finalizing again after five minutes', async () => {
      const w = await world()
      const c = await newClient(w)
      const order = await readyOrder(c, ['localhost'])
      const id = order.url.split('/').pop()!
      await query()`update acme_orders set status = 'processing', updated_at = now() - interval '4 minutes' where id = ${id}`
      expect((await c.client.getOrder(order)).status).toBe('processing')
      await query()`update acme_orders set updated_at = now() - interval '6 minutes' where id = ${id}`
      expect((await c.client.getOrder(order)).status).toBe('ready')
      const { csr } = await csrFor(['localhost'])
      expect((await c.client.finalizeOrder(order, csr)).status).toBe('valid')
    })

    it('marks the challenge, the authorization and the order invalid when the answer is wrong', async () => {
      const w = await world()
      const c = await newClient(w)
      const order = await c.client.createOrder({ identifiers: [{ type: 'dns', value: 'localhost' }] })
      const [authz] = await c.client.getAuthorizations(order)
      const challenge = authz!.challenges.find((ch: any) => ch.type === 'http-01')!
      // Nothing is served for the token.
      await c.client.completeChallenge(challenge)
      expect(await messageOf(c.client.waitForValidStatus(challenge))).toMatch(/unauthorized|403|status/i)

      const rows = await query()`select c.status as challenge, a.status as authorization, o.status as "order", c.error, o.error as order_error
        from acme_challenges c join acme_authorizations a on a.id = c.authorization_id join acme_orders o on o.id = a.order_id where c.type = 'http-01'`
      expect(rows[0]).toMatchObject({ challenge: 'invalid', authorization: 'invalid', order: 'invalid' })
      expect(rows[0]!.error.type).toBe(`${URN}unauthorized`)
      expect(rows[0]!.order_error.type).toBe(`${URN}unauthorized`)
      expect((await c.client.getOrder(order)).status).toBe('invalid')
      const { csr } = await csrFor(['localhost'])
      expect(await messageOf(c.client.finalizeOrder(order, csr))).toMatch(/not ready/i)
    })

    it('does not start a second challenge of an authorization, and ignores a ready signal after it is decided', async () => {
      const w = await world()
      const c = await newClient(w)
      const order = await readyOrder(c, ['localhost'])
      const [authz] = await c.client.getAuthorizations(order)
      expect(authz!.status).toBe('valid')
      const tls = authz!.challenges.find((ch: any) => ch.type === 'tls-alpn-01')!
      const res = await c.raw.post(tls.url, {}, c.client.getAccountUrl())
      expect(res.status).toBe(200)
      expect(res.json.status).toBe('pending')
      expect(res.headers.get('link')).toContain('rel="up"')
    })
  })

  describe('issuing', () => {
    it('issues with http-01 for a name and an address, with the template’s lifetime and default tags', async () => {
      const w = await world()
      const c = await newClient(w)
      const { certificate } = await enroll(c, ['localhost', '127.0.0.1'], 'http-01')

      const list = (await w.operator.rpc('certificates.list', { source: 'acme' })).body.data
      expect(list).toHaveLength(1)
      const issued = list[0]
      expect(issued).toMatchObject({ source: 'acme', status: 'active', template: { slug: 'web' }, requested_by_user_id: null, requested_by_api_key_id: null })
      expect(issued.tags.map((t: any) => t.name)).toEqual(['Automated'])
      expect(issued.sans).toEqual(expect.arrayContaining([{ type: 'dns', value: 'localhost' }, { type: 'ip', value: '127.0.0.1' }]))
      const lifetime = (new Date(issued.not_after).getTime() - new Date(issued.not_before).getTime()) / 1000
      expect(lifetime).toBeGreaterThan(30 * DAY)
      expect(lifetime).toBeLessThan(30 * DAY + 600)

      const [event] = await query()`select actor_type, actor_id, data from events where name = 'certificates.issue'`
      expect(event).toMatchObject({ actor_type: 'acme' })
      expect(event!.data).toMatchObject({ source: 'acme', template_id: w.web.id })
      const [account] = await query()`select id from acme_accounts`
      expect(event!.actor_id).toBe(account!.id)

      // The chain is leaf, issuing CA, root (the root is for the client's trust store anyway).
      expect(certificate.match(/-----BEGIN CERTIFICATE-----/g)).toHaveLength(3)
      if (!hasOpenssl) return
      const tmp = scratch()
      try {
        const [leaf, issuing, root] = certificate.trim().split(/(?<=-----END CERTIFICATE-----)\s*/).filter(Boolean)
        tmp.write('leaf.pem', leaf!)
        tmp.write('issuing.pem', issuing!)
        tmp.write('root.pem', w.root.active_certificate.pem)
        expect(tmp.status(['verify', '-CAfile', 'root.pem', '-untrusted', 'issuing.pem', 'leaf.pem'])).toMatchObject({ code: 0 })
        expect(root!.replace(/\s/g, '')).toBe(w.root.active_certificate.pem.replace(/\s/g, ''))
        const text = tmp.run(['x509', '-in', 'leaf.pem', '-noout', '-text'])
        expect(text).toMatch(/DNS:localhost/)
        expect(text).toMatch(/IP Address:127\.0\.0\.1/)
        expect(text).toMatch(/TLS Web Server Authentication/)
      } finally {
        tmp.cleanup()
      }
    })

    it('issues with tls-alpn-01 for a name and, with the reverse DNS name as SNI, for an address', async () => {
      const w = await world()
      const c = await newClient(w, { rsa: true })
      const { certificate } = await enroll(c, ['localhost', '127.0.0.1'], 'tls-alpn-01')
      expect(certificate).toContain('BEGIN CERTIFICATE')
      expect((await w.viewer.rpc('certificates.list', { source: 'acme' })).body.data).toHaveLength(1)
      const [{ n }] = await query()`select count(*)::int as n from acme_challenges where type = 'tls-alpn-01' and status = 'valid'`
      expect(n).toBe(2)
    })

    it('revokes with the account that ordered the certificate, and not twice', async () => {
      const w = await world()
      const c = await newClient(w)
      const { certificate } = await enroll(c, ['localhost'], 'http-01')
      const id = (await w.operator.rpc('certificates.list', { source: 'acme' })).body.data[0].id

      await c.client.revokeCertificate(leafOf(certificate), { reason: 1 })
      const revoked = (await w.operator.rpc('certificates.get', { id })).body.data
      expect(revoked).toMatchObject({ status: 'revoked', revocation_reason: 'key_compromise' })
      const [event] = await query()`select actor_type from events where name = 'certificates.revoke'`
      expect(event!.actor_type).toBe('acme')

      const der = acme.crypto.getPemBodyAsB64u(leafOf(certificate))
      const again = await c.raw.post(c.raw.url('revoke-cert'), { certificate: der }, c.client.getAccountUrl())
      expect(again).toMatchObject({ status: 400, json: { type: `${URN}alreadyRevoked` } })
    })

    it('revokes with the certificate’s own key, but not with a stranger’s account or key, or a reason certifly does not use', async () => {
      const w = await world()
      const c = await newClient(w)
      const stranger = await newClient(w)
      const { certificate, key } = await enroll(c, ['localhost'], 'http-01')
      const id = (await w.operator.rpc('certificates.list', { source: 'acme' })).body.data[0].id
      const der = acme.crypto.getPemBodyAsB64u(leafOf(certificate))
      const url = c.raw.url('revoke-cert')

      expect((await stranger.raw.post(url, { certificate: der }, stranger.client.getAccountUrl())).json.type).toBe(`${URN}unauthorized`)
      expect((await new RawAcme(`${origin}/acme/web`).postWithJwk(url, { certificate: der })).json.type).toBe(`${URN}unauthorized`)
      expect((await c.raw.post(url, { certificate: der, reason: 6 }, c.client.getAccountUrl())).json.type).toBe(`${URN}badRevocationReason`)
      expect((await c.raw.post(url, { certificate: 'AAAA' }, c.client.getAccountUrl())).status).toBe(404)
      expect((await w.operator.rpc('certificates.get', { id })).body.data.status).toBe('active')

      const withKey = new RawAcme(`${origin}/acme/web`, key)
      const done = await withKey.postWithJwk(url, { certificate: der, reason: 1 })
      expect(done.status).toBe(200)
      expect((await w.operator.rpc('certificates.get', { id })).body.data).toMatchObject({ status: 'revoked', revocation_reason: 'key_compromise' })
    })

    it('downloads the chain only for the account that ordered it', async () => {
      const w = await world()
      const c = await newClient(w)
      const stranger = await newClient(w)
      const order = await readyOrder(c, ['localhost'])
      const { csr } = await csrFor(['localhost'])
      const finalized = await c.client.finalizeOrder(order, csr)
      const asOwner = await c.raw.post(finalized.certificate, '', c.client.getAccountUrl())
      expect(asOwner.status).toBe(200)
      expect(asOwner.headers.get('content-type')).toBe('application/pem-certificate-chain')
      expect(asOwner.text.match(/-----BEGIN CERTIFICATE-----/g)).toHaveLength(3)
      expect((await stranger.raw.post(finalized.certificate, '', stranger.client.getAccountUrl())).status).toBe(404)
    })

    it('applies the template: a key type it does not allow is a bad CSR', async () => {
      const w = await world()
      expect((await w.admin.rpc('templates.update', { id: w.web.id, key_algorithms: ['ecdsa-p384'] })).status).toBe(200)
      const c = await newClient(w)
      const order = await readyOrder(c, ['localhost'])
      const { csr } = await csrFor(['localhost'])
      expect(await messageOf(c.client.finalizeOrder(order, csr))).toMatch(/ecdsa-p256/)
      expect((await c.client.getOrder(order)).status).toBe('ready')
    })
  })

  describe('binding keys', () => {
    it('are created with step-up, show the HMAC key once, and are listed without it', async () => {
      const w = await world()
      const created = await w.admin.rpc('acme_eab_keys.create', { template_id: w.web.id, name: 'build agents' })
      expect(created.status).toBe(200)
      expect(created.headers.get('cache-control')).toBe('no-store')
      const key = created.body.data
      expect(key).toMatchObject({ name: 'build agents', template_id: w.web.id, last_used_at: null, revoked_at: null, permissions: { revoke: true } })
      expect(key.kid).toBeTruthy()
      expect(Buffer.from(key.hmac_key, 'base64url')).toHaveLength(32)

      const list = await w.viewer.rpc('acme_eab_keys.list', { template_id: w.web.id })
      expect(list.status).toBe(200)
      expect(list.body.data).toHaveLength(1)
      expect(list.body.data[0]).toMatchObject({ id: key.id, kid: key.kid, permissions: { revoke: false } })
      expect(JSON.stringify(list.body)).not.toContain(key.hmac_key)
      expect(Object.keys(list.body.data[0]).sort()).toEqual(['created_at', 'id', 'kid', 'last_used_at', 'name', 'permissions', 'revoked_at', 'template_id'])

      const [row] = await query()`select hmac_key_encrypted from acme_eab_keys`
      expect(row!.hmac_key_encrypted).not.toContain(key.hmac_key)
      const events = await query()`select name, data from events where name like 'acme_eab_keys.%'`
      expect(events.map((e) => e.name)).toEqual(['acme_eab_keys.create'])
      expect(JSON.stringify(events)).not.toContain(key.hmac_key)
    })

    it('are only for admins with a fresh session, never API keys, and revoking is repeatable', async () => {
      const w = await world()
      const apiKey = (await w.admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
      const body = { template_id: w.web.id, name: 'x' }
      expect((await w.operator.rpc('acme_eab_keys.create', body)).status).toBe(403)
      expect((await w.viewer.rpc('acme_eab_keys.create', body)).status).toBe(403)
      expect((await new Client().rpcWithKey(apiKey, 'acme_eab_keys.create', body)).status).toBe(403)
      expect((await new Client().rpc('acme_eab_keys.list', { template_id: w.web.id })).status).toBe(401)
      expect((await w.admin.rpc('acme_eab_keys.create', { template_id: crypto.randomUUID(), name: 'x' })).body.error.code).toBe('template_not_found')
      expect((await w.admin.rpc('acme_eab_keys.create', { template_id: w.web.id, name: '' })).status).toBe(400)

      const key = await eabKey(w)
      await ageSessions(30)
      expect(await w.admin.rpc('acme_eab_keys.create', body)).toMatchObject({ status: 403, body: { error: { code: 'reauth_required' } } })
      expect(await w.admin.rpc('acme_eab_keys.revoke', { id: key.id })).toMatchObject({ status: 403, body: { error: { code: 'reauth_required' } } })
      expect((await w.operator.rpc('acme_eab_keys.revoke', { id: key.id })).status).toBe(403)
      expect((await w.viewer.rpc('acme_eab_keys.list', { template_id: w.web.id })).body.data).toHaveLength(1)
      const [{ n }] = await query()`select count(*)::int as n from acme_eab_keys where revoked_at is not null`
      expect(n).toBe(0)
    })

    it('revoke at once and record it', async () => {
      const w = await world()
      const key = await eabKey(w)
      const revoked = await w.admin.rpc('acme_eab_keys.revoke', { id: key.id })
      expect(revoked.body.data).toMatchObject({ id: key.id, permissions: { revoke: false } })
      expect(revoked.body.data.revoked_at).not.toBeNull()
      const again = await w.admin.rpc('acme_eab_keys.revoke', { id: key.id })
      expect(again.body.data.revoked_at).toBe(revoked.body.data.revoked_at)
      expect((await w.admin.rpc('acme_eab_keys.revoke', { id: crypto.randomUUID() })).status).toBe(404)
      const [{ n }] = await query()`select count(*)::int as n from events where name = 'acme_eab_keys.revoke'`
      expect(n).toBe(1)
    })
  })

  describe('cleanup', () => {
    let core: Awaited<ReturnType<typeof coreContext>>
    beforeAll(async () => {
      core = await coreContext()
    })
    afterAll(() => core.close())

    it('removes nonces that expired and orders that ended long ago', async () => {
      const w = await world()
      const c = await newClient(w)
      const order = await c.client.createOrder({ identifiers: [{ type: 'dns', value: 'localhost' }] })
      await query()`insert into acme_nonces (nonce, expires_at) values ('old', now() - interval '1 hour'), ('fresh', now() + interval '1 hour')`
      const result = await cleanupExpired(core.ctx)
      expect(result.acme_nonces).toBeGreaterThanOrEqual(1)
      expect((await query()`select nonce from acme_nonces where nonce in ('old', 'fresh')`).map((r) => r.nonce)).toEqual(['fresh'])
      expect(result.acme_orders).toBe(0)

      await query()`update acme_orders set expires_at = now() - interval '40 days'`
      expect((await cleanupExpired(core.ctx)).acme_orders).toBe(1)
      expect((await query()`select id from acme_authorizations`).length).toBe(0)
      expect(order.url).toBeTruthy()
    })
  })
})
