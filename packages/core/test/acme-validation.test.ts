// acme-client first: its x509 needs the full reflect-metadata, which pki's small shim leaves alone only when it is already there.
import acme from 'acme-client'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createSecureContext, createServer as createTlsServer, type SecureContext, type Server as TlsServer } from 'node:tls'
import { reverseDnsName } from '@certifly/pki'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { MAX_REDIRECTS, validateHttp01, validateTlsAlpn01 } from '../src/acme-validation'

const KEY_AUTH = 'tok.thumb'
const host = { type: 'dns', value: 'localhost' } as const

async function listen<T extends Server | TlsServer>(server: T): Promise<{ server: T; port: number }> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, port: (server.address() as AddressInfo).port }
}

describe('http-01 validation', () => {
  let port = 0
  let server: Server
  beforeAll(async () => {
    ;({ server, port } = await listen(
      createServer((req, res) => {
        const url = new URL(req.url ?? '/', 'http://x')
        const path = url.pathname
        if (path.endsWith('/ok')) return void res.writeHead(200).end(`${KEY_AUTH}\r\n \n`)
        if (path.endsWith('/wrong')) return void res.writeHead(200).end('something else')
        if (path.endsWith('/missing')) return void res.writeHead(404).end('no')
        if (path.endsWith('/big')) return void res.writeHead(200).end('a'.repeat(100_000))
        if (path.endsWith('/hang')) return
        if (path.endsWith('/loop')) return void res.writeHead(302, { location: '/loop' }).end()
        if (path.endsWith('/to-ok')) return void res.writeHead(301, { location: '/ok' }).end()
        if (path.endsWith('/to-absolute')) return void res.writeHead(307, { location: `http://localhost:${port}/ok` }).end()
        if (path.endsWith('/to-other-host')) return void res.writeHead(302, { location: `http://127.0.0.1:${port}/ok` }).end()
        if (path.endsWith('/to-other-port')) return void res.writeHead(302, { location: 'http://localhost:2375/ok' }).end()
        if (path.endsWith('/to-ftp')) return void res.writeHead(302, { location: 'ftp://localhost/ok' }).end()
        if (path.endsWith('/to-ok-after-two')) return void res.writeHead(302, { location: '/to-ok' }).end()
        res.writeHead(404).end()
      }),
    ))
  })
  afterAll(() => new Promise((resolve) => server.close(resolve)))

  // The token is the last path segment, so the fixtures above can be told apart by it.
  const check = (token: string, options = {}, identifier: { type: 'dns' | 'ip'; value: string } = host) => validateHttp01(identifier, token, KEY_AUTH, port, options)

  it('accepts the key authorization, ignoring whitespace at the end', async () => {
    expect(await check('ok')).toBeNull()
  })

  it('follows redirects on the same host, up to ten', async () => {
    expect(await check('to-ok')).toBeNull()
    expect(await check('to-absolute')).toBeNull()
    expect(await check('to-ok-after-two')).toBeNull()
    expect(await check('loop')).toMatchObject({ type: 'incorrectResponse', detail: `More than ${MAX_REDIRECTS} redirects` })
  })

  it('refuses redirects that leave http and https', async () => {
    expect(await check('to-ftp')).toMatchObject({ type: 'incorrectResponse' })
  })

  it('refuses redirects to another host, even another name for the same machine', async () => {
    expect(await check('to-other-host')).toEqual({ type: 'incorrectResponse', detail: 'The redirect leaves localhost' })
  })

  it('refuses redirects to another port on the same host', async () => {
    expect(await check('to-other-port')).toEqual({ type: 'incorrectResponse', detail: 'The redirect goes to port 2375' })
  })

  it('reports a wrong answer, a missing file and an oversized body without echoing the body', async () => {
    expect(await check('wrong')).toEqual({ type: 'incorrectResponse', detail: 'The answer is not the expected key authorization' })
    expect(await check('missing')).toMatchObject({ type: 'unauthorized', detail: expect.stringContaining('404') })
    expect(await check('big')).toMatchObject({ type: 'incorrectResponse' })
  })

  it('gives up on a server that does not answer', async () => {
    const started = Date.now()
    expect(await check('hang', { timeout_ms: 300 })).toMatchObject({ type: 'connection', detail: 'The connection timed out' })
    expect(Date.now() - started).toBeLessThan(3000)
  })

  it('reports a closed port, and reaches an IP identifier', async () => {
    const { server: closed, port: freePort } = await listen(createServer())
    await new Promise((resolve) => closed.close(resolve))
    expect(await validateHttp01(host, 'ok', KEY_AUTH, freePort)).toMatchObject({ type: 'connection' })
    expect(await check('ok', {}, { type: 'ip', value: '127.0.0.1' })).toBeNull()
  })
})

describe('tls-alpn-01 validation', () => {
  const contexts = new Map<string, SecureContext>()
  let port = 0
  let server: TlsServer
  let plainPort = 0
  let plain: TlsServer
  beforeAll(async () => {
    const handler = (socket: import('node:tls').TLSSocket) => {
      socket.on('error', () => {})
      socket.end()
    }
    ;({ server, port } = await listen(createTlsServer({ ALPNProtocols: ['acme-tls/1'], SNICallback: (name, done) => done(null, contexts.get(name)) }, handler)))
    // A server that offers no ALPN at all.
    const [key, cert] = await acme.crypto.createAlpnCertificate({ identifier: host } as never, KEY_AUTH, await acme.crypto.createPrivateEcdsaKey())
    ;({ server: plain, port: plainPort } = await listen(createTlsServer({ key: key.toString(), cert: cert.toString() }, handler)))
    server.on('tlsClientError', () => {})
    plain.on('tlsClientError', () => {})
  })
  afterAll(async () => {
    await Promise.all([new Promise((resolve) => server.close(resolve)), new Promise((resolve) => plain.close(resolve))])
  })

  async function present(identifier: { type: 'dns' | 'ip'; value: string }, forAuthz: { type: 'dns' | 'ip'; value: string }, keyAuthorization: string) {
    const [key, cert] = await acme.crypto.createAlpnCertificate({ identifier: forAuthz } as never, keyAuthorization, await acme.crypto.createPrivateEcdsaKey())
    contexts.set(identifier.type === 'ip' ? reverseDnsName(identifier.value) : identifier.value, createSecureContext({ key: key.toString(), cert: cert.toString() }))
  }

  it('accepts a certificate for the name with the digest of the key authorization', async () => {
    await present(host, host, KEY_AUTH)
    expect(await validateTlsAlpn01(host, KEY_AUTH, port)).toBeNull()
  })

  it('accepts an IP identifier, asking by its reverse DNS name', async () => {
    const ip = { type: 'ip', value: '127.0.0.1' } as const
    await present(ip, ip, KEY_AUTH)
    expect(await validateTlsAlpn01(ip, KEY_AUTH, port)).toBeNull()
  })

  it('refuses a certificate with another key authorization or another name', async () => {
    await present(host, host, 'someone.else')
    expect(await validateTlsAlpn01(host, KEY_AUTH, port)).toMatchObject({ type: 'incorrectResponse', detail: expect.stringContaining('does not match') })
    await present(host, { type: 'dns', value: 'other.test' }, KEY_AUTH)
    expect(await validateTlsAlpn01(host, KEY_AUTH, port)).toMatchObject({ type: 'incorrectResponse', detail: expect.stringContaining('only subject alternative name') })
  })

  it('refuses a server that does not select acme-tls/1, and reports a closed port', async () => {
    expect(await validateTlsAlpn01(host, KEY_AUTH, plainPort)).toMatchObject({ type: 'tls' })
    const { server: closed, port: freePort } = await listen(createServer())
    await new Promise((resolve) => closed.close(resolve))
    expect(await validateTlsAlpn01(host, KEY_AUTH, freePort)).toMatchObject({ type: 'connection' })
  })
})
