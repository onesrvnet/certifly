import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { canonicalIp, inspectAcmeChallengeCertificate, keyAuthorizationDigest, reverseDnsName } from '@certifly/pki'

/*
 * What certifly does to check an ACME challenge from the outside: http-01 (RFC 8555 §8.3) and
 * tls-alpn-01 (RFC 8737). Each check returns null when the challenge is met, or the problem to
 * record. Nothing from the answered body or certificate is passed on beyond a short reason.
 */

export interface ChallengeProblem {
  /** The ACME error type, without its `urn:ietf:params:acme:error:` prefix. */
  type: 'connection' | 'tls' | 'incorrectResponse' | 'unauthorized'
  detail: string
}

export interface ValidationIdentifier {
  type: 'dns' | 'ip'
  value: string
}

export interface ValidationOptions {
  /** Per connection, milliseconds. */
  timeout_ms?: number
  /** For the whole check, redirects included. */
  deadline_ms?: number
}

export const MAX_REDIRECTS = 10
const DEFAULT_TIMEOUT_MS = 10_000
const DEFAULT_DEADLINE_MS = 20_000
/** A key authorization is under 120 bytes; anything much longer is not one. */
const MAX_BODY_BYTES = 4096

const problem = (type: ChallengeProblem['type'], detail: string): ChallengeProblem => ({ type, detail })

interface FetchedPage {
  status: number
  location?: string
  body: string
  oversize: boolean
}

function fetchPage(url: URL, timeout_ms: number): Promise<FetchedPage> {
  return new Promise((resolve, reject) => {
    const secure = url.protocol === 'https:'
    const host = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname
    const make = secure ? httpsRequest : httpRequest
    const req = make(
      {
        host,
        port: url.port ? Number(url.port) : secure ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        headers: { accept: '*/*', 'user-agent': 'certifly-acme-validation' },
        // A fresh connection every time: no keep-alive pool shared with anything else.
        agent: false,
        timeout: timeout_ms,
        // RFC 8555 §8.3: the certificate of an https redirect is not checked.
        ...(secure ? { rejectUnauthorized: false } : {}),
      },
      (res) => {
        const chunks: Buffer[] = []
        let size = 0
        let oversize = false
        res.on('data', (chunk: Buffer) => {
          size += chunk.length
          if (size > MAX_BODY_BYTES) {
            oversize = true
            req.destroy()
            resolve({ status: res.statusCode ?? 0, location: res.headers.location, body: '', oversize })
            return
          }
          chunks.push(chunk)
        })
        res.on('end', () => resolve({ status: res.statusCode ?? 0, location: res.headers.location, body: Buffer.concat(chunks).toString('utf8'), oversize }))
        res.on('error', reject)
      },
    )
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })))
    req.on('error', reject)
    req.end()
  })
}

/** `[::1]` for IPv6 literals, so the address fits into a URL. */
const urlHost = (identifier: ValidationIdentifier) => (identifier.value.includes(':') ? `[${identifier.value}]` : identifier.value)

/**
 * http-01: GET `http://<identifier>:<port>/.well-known/acme-challenge/<token>` must answer 200
 * with the key authorization (trailing whitespace ignored). Redirects to http or https are
 * followed, at most ten, within 20 seconds in all.
 */
export async function validateHttp01(
  identifier: ValidationIdentifier,
  token: string,
  keyAuthorization: string,
  port: number,
  options: ValidationOptions = {},
): Promise<ChallengeProblem | null> {
  const timeout = options.timeout_ms ?? DEFAULT_TIMEOUT_MS
  const deadline = Date.now() + (options.deadline_ms ?? DEFAULT_DEADLINE_MS)
  let url = new URL(`http://${urlHost(identifier)}:${port}/.well-known/acme-challenge/${encodeURIComponent(token)}`)
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const left = deadline - Date.now()
    if (left <= 0) return problem('connection', 'The check took too long')
    let page: FetchedPage
    try {
      page = await fetchPage(url, Math.min(timeout, left))
    } catch (error) {
      const code = (error as { code?: string }).code
      return problem('connection', code === 'ETIMEDOUT' ? 'The connection timed out' : `Could not connect to ${url.hostname}:${url.port || '80'}${code ? ` (${code})` : ''}`)
    }
    if (page.status >= 300 && page.status < 400 && page.location) {
      let next: URL
      try {
        next = new URL(page.location, url)
      } catch {
        return problem('incorrectResponse', 'The redirect target is not a valid URL')
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') return problem('incorrectResponse', 'The redirect leaves http and https')
      // Only within the host being validated: a redirect must not make certifly request other hosts on its network.
      if (next.hostname.toLowerCase() !== url.hostname.toLowerCase()) return problem('incorrectResponse', `The redirect leaves ${url.hostname}`)
      // Nor other services on that host: only the validation port and the standard web ports (RFC 8555 §8.3).
      const nextPort = Number(next.port || (next.protocol === 'https:' ? 443 : 80))
      if (nextPort !== port && nextPort !== 80 && nextPort !== 443) return problem('incorrectResponse', `The redirect goes to port ${nextPort}`)
      url = next
      continue
    }
    if (page.oversize) return problem('incorrectResponse', 'The answer is far longer than a key authorization')
    if (page.status !== 200) return problem('unauthorized', `The challenge URL answered with status ${page.status}`)
    if (page.body.replace(/\s+$/, '') !== keyAuthorization) return problem('incorrectResponse', 'The answer is not the expected key authorization')
    return null
  }
  return problem('incorrectResponse', `More than ${MAX_REDIRECTS} redirects`)
}

/**
 * tls-alpn-01: connect to `<identifier>:<port>` offering ALPN `acme-tls/1`. The SNI is the name
 * itself, or for an IP identifier its reverse DNS name (RFC 8738 §6). The certificate must have
 * exactly that name as its only SAN and a critical acmeIdentifier extension holding the SHA-256
 * of the key authorization.
 */
export async function validateTlsAlpn01(
  identifier: ValidationIdentifier,
  keyAuthorization: string,
  port: number,
  options: ValidationOptions = {},
): Promise<ChallengeProblem | null> {
  const timeout = Math.min(options.timeout_ms ?? DEFAULT_TIMEOUT_MS, options.deadline_ms ?? DEFAULT_DEADLINE_MS)
  const servername = identifier.type === 'ip' ? reverseDnsName(identifier.value) : identifier.value
  let socket: TLSSocket | undefined
  try {
    socket = await new Promise<TLSSocket>((resolve, reject) => {
      const s = tlsConnect({ host: identifier.value, port, servername, ALPNProtocols: ['acme-tls/1'], rejectUnauthorized: false, timeout })
      s.once('secureConnect', () => resolve(s))
      s.once('timeout', () => s.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })))
      s.once('error', reject)
    })
  } catch (error) {
    const code = (error as { code?: string }).code
    const tlsFailure = typeof code === 'string' && (code.startsWith('ERR_SSL') || code.startsWith('ERR_TLS') || code === 'ECONNRESET')
    return problem(tlsFailure ? 'tls' : 'connection', code === 'ETIMEDOUT' ? 'The connection timed out' : `Could not complete a TLS handshake with ${identifier.value}:${port}${code ? ` (${code})` : ''}`)
  }
  try {
    if (socket.alpnProtocol !== 'acme-tls/1') return problem('tls', 'The server did not select the acme-tls/1 protocol')
    const peer = socket.getPeerCertificate()
    if (!peer?.raw) return problem('incorrectResponse', 'The server presented no certificate')
    let certificate
    try {
      certificate = inspectAcmeChallengeCertificate(new Uint8Array(peer.raw))
    } catch {
      return problem('incorrectResponse', 'The presented certificate cannot be read')
    }
    const { sans, unsupported_sans, acme_identifier } = certificate
    const only = sans[0]
    const nameMatches =
      sans.length === 1 &&
      unsupported_sans.length === 0 &&
      !!only &&
      (identifier.type === 'ip' ? only.type === 'ip' && only.value === canonicalIp(identifier.value) : only.type === 'dns' && only.value === identifier.value)
    if (!nameMatches) return problem('incorrectResponse', 'The certificate must have the identifier as its only subject alternative name')
    if (!acme_identifier) return problem('incorrectResponse', 'The certificate has no acmeIdentifier extension')
    if (!acme_identifier.critical) return problem('incorrectResponse', 'The acmeIdentifier extension must be critical')
    if (acme_identifier.digest_hex !== keyAuthorizationDigest(keyAuthorization)) return problem('incorrectResponse', 'The acmeIdentifier does not match the key authorization')
    return null
  } finally {
    socket.destroy()
  }
}
