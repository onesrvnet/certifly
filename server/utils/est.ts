import type { H3Event } from 'h3'
import { safeEqualString } from '@certifly/core/crypto'
import { AppError, AuthenticationError } from '@certifly/core/errors'
import { findEstTemplate } from '@certifly/core/est'
import type { TemplateRow } from '@certifly/core/templates'

/** What a client that sent no or wrong credentials is told to use (RFC 7617). */
const BASIC_CHALLENGE = 'Basic realm="certifly EST"'
/** A PKCS#10 request is a few kilobytes; anything near this is not one. */
const MAX_BODY_BYTES = 64 * 1024

/** EST errors are short plain text (RFC 7030 §4.2.3), not the JSON of the v2 API. */
function estFailure(event: H3Event, status: number, message: string) {
  setResponseStatus(event, status)
  setResponseHeader(event, 'content-type', 'text/plain; charset=utf-8')
  if (status === 401) setResponseHeader(event, 'www-authenticate', BASIC_CHALLENGE)
  return message
}

/**
 * A handler for `/.well-known/est/<template-slug>/...`: counts the request against the limit
 * and finds the template (404 unless it is active and allows EST), and maps errors from core to
 * plain-text answers. Authentication is the handler's own business.
 */
export function defineEstHandler(handler: (event: H3Event, template: TemplateRow) => Promise<unknown>) {
  return defineEventHandler(async (event) => {
    try {
      await limit(event, 'est', clientIp(event))
      const slug = caSlug(getRouterParam(event, 'slug'))
      const template = slug ? await findEstTemplate(useContext(), slug) : null
      if (!template) return estFailure(event, 404, 'Not found')
      return await handler(event, template)
    } catch (error) {
      if (error instanceof AppError) return estFailure(event, error.status, error.message)
      if (isError(error) && error.statusCode < 500) throw error
      logServerError(`[est] ${event.path} failed`, error, { path: event.path })
      return estFailure(event, 500, 'Something went wrong')
    }
  })
}

/** The username and password of an `Authorization: Basic` header, or a 401. */
export function basicCredentials(event: H3Event): { username: string; password: string } {
  const header = getRequestHeader(event, 'authorization') ?? ''
  const match = /^basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header)
  const decoded = match ? Buffer.from(match[1]!, 'base64').toString('utf8') : ''
  const colon = decoded.indexOf(':')
  if (colon < 1) throw new AuthenticationError('Authentication required')
  return { username: decoded.slice(0, colon), password: decoded.slice(colon + 1) }
}

/** The request body (a base64 PKCS#10), size-limited. */
export async function estRequestBody(event: H3Event): Promise<Buffer> {
  const body = await readCappedBody(event, MAX_BODY_BYTES)
  if (body === null) throw new AppError(413, 'payload_too_large', 'The request is too large')
  if (!body || body.length === 0) throw new AppError(400, 'validation_error', 'The request body is empty')
  return body
}

let warnedAboutProxySecret = false

/**
 * The forwarded client certificate of a request, or undefined when it cannot be trusted. Anyone
 * can read a certificate, so the header only counts when `TRUST_PROXY` is on, `EST_PROXY_SECRET`
 * is set and the request carries it (compared as SHA-256 digests, in constant time).
 */
export function trustedClientCertificateHeader(event: H3Event): string | undefined {
  const config = env()
  if (!config.TRUST_PROXY || !config.EST_PROXY_SECRET) {
    if (!warnedAboutProxySecret) {
      warnedAboutProxySecret = true
      console.warn('[est] re-enrollment is off: set TRUST_PROXY=true and EST_PROXY_SECRET (the proxy sends it in the EST_PROXY_SECRET_HEADER header) to enable it')
    }
    return undefined
  }
  const sent = getRequestHeader(event, config.EST_PROXY_SECRET_HEADER)
  if (!sent || !safeEqualString(sent, config.EST_PROXY_SECRET)) return undefined
  return getRequestHeader(event, config.EST_CLIENT_CERT_HEADER)
}

/** A certs-only PKCS#7 answer as base64 (RFC 7030 §4.1.3, §4.2.3). */
export function sendEstCertificates(event: H3Event, base64: string, options: { smime: boolean; cache: boolean }) {
  setResponseHeaders(event, {
    'content-type': options.smime ? 'application/pkcs7-mime; smime-type=certs-only' : 'application/pkcs7-mime',
    'content-transfer-encoding': 'base64',
    'cache-control': options.cache ? 'public, max-age=300' : 'no-store',
  })
  return base64
}
