import type { H3Event } from 'h3'
import {
  acmeDirectory,
  acmeDirectoryLink,
  AcmeError,
  type AcmeOperation,
  acmeProblem,
  type AcmeResult,
  findAcmeTemplate,
  handleAcmePost,
  issueAcmeNonce,
} from '@certifly/core/acme'
import { AppError } from '@certifly/core/errors'

/** A signed request is a few kilobytes at most (a CSR in a JWS). */
const MAX_BODY_BYTES = 64 * 1024

/**
 * Runs one ACME request and sends the answer the way RFC 8555 asks: every response has a fresh
 * `Replay-Nonce` and a `Link` to the directory and is never cached, and errors are
 * `application/problem+json`. An unknown or disabled directory answers 404 without either.
 */
async function respond(event: H3Event, slug: string, run: () => Promise<AcmeResult>) {
  const ctx = useContext()
  setResponseHeader(event, 'cache-control', 'no-store')
  let result: AcmeResult
  try {
    try {
      await limit(event, 'acme', clientIp(event))
    } catch (error) {
      if (isError(error) && error.statusCode === 429) throw new AcmeError(429, 'rateLimited', 'Too many requests, try again later')
      throw error
    }
    result = await run()
  } catch (error) {
    if (!(error instanceof AppError)) logServerError(`[acme] ${event.path} failed`, error, { path: event.path })
    const problem = acmeProblem(error)
    result = { status: problem.status, body: JSON.stringify(problem.body), content_type: 'application/problem+json' }
  }

  // A missing directory has nothing to link to; everything else is told where to start and what to sign next.
  if (result.status !== 404 || (await findAcmeTemplate(ctx, slug).then(() => true, () => false))) {
    setResponseHeaders(event, { 'replay-nonce': await issueAcmeNonce(ctx) })
    setResponseHeader(event, 'link', [acmeDirectoryLink(ctx, slug), ...(result.link ?? [])])
  }
  if (result.location) setResponseHeader(event, 'location', result.location)
  setResponseStatus(event, result.status)
  const json = typeof result.body !== 'string' && result.body !== undefined
  return send(event, json ? JSON.stringify(result.body) : ((result.body as string | undefined) ?? ''), result.content_type ?? 'application/json')
}

const slugOf = (event: H3Event) => getRouterParam(event, 'slug') ?? ''

/** A signed POST to an ACME endpoint (`application/jose+json`). */
export function defineAcmePost(operation: AcmeOperation) {
  return defineEventHandler((event) =>
    respond(event, slugOf(event), async () => {
      const bytes = await readCappedBody(event, MAX_BODY_BYTES)
      if (bytes === null) throw new AcmeError(400, 'malformed', 'The request is too large')
      if (!bytes || bytes.length === 0) throw new AcmeError(400, 'malformed', 'The request has no body')
      const raw = bytes.toString('utf8')
      let body: unknown
      try {
        body = JSON.parse(raw)
      } catch {
        throw new AcmeError(400, 'malformed', 'The request body is not JSON')
      }
      return handleAcmePost(useContext(), operation, {
        slug: slugOf(event),
        path: event.path.split('?')[0]!,
        content_type: getHeader(event, 'content-type'),
        body,
        id: getRouterParam(event, 'id'),
        ip: requestIp(event),
      })
    }),
  )
}

/** `GET /acme/<slug>/directory`. */
export const defineAcmeDirectory = () =>
  defineEventHandler((event) => respond(event, slugOf(event), async () => ({ status: 200, body: await acmeDirectory(useContext(), slugOf(event)) })))

/** `HEAD` (200) and `GET` (204) of `/acme/<slug>/new-nonce`; the nonce is in the header of every response. */
export const defineAcmeNewNonce = (status: 200 | 204) =>
  defineEventHandler((event) =>
    respond(event, slugOf(event), async () => {
      await findAcmeTemplate(useContext(), slugOf(event))
      return { status, body: '' }
    }),
  )
