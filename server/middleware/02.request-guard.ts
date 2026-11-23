import type { H3Event } from 'h3'
import { AppError } from '@certifly/core/errors'

const PAYLOAD_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * The API refuses state-changing requests from another origin. The session cookie is
 * SameSite=Lax, so a page on a sibling subdomain counts as same-site and its form posts carry
 * the cookie; h3 parses such a form body into an object a handler would accept. Browsers always
 * send Origin on these requests. The CLI, API keys and hosts send none and are not affected.
 *
 * Bodies whose declared length is over the API's limit are refused here, before anything reads
 * them; handlers count chunked bodies as they read them (`readCappedBody`).
 */
export default defineEventHandler((event) => {
  if (!PAYLOAD_METHODS.has(event.method)) return
  if (event.path.startsWith('/api/')) {
    const origin = getRequestHeader(event, 'origin')
    if (origin !== undefined && origin !== new URL(env().URL).origin) {
      return refuse(event, new AppError(403, 'cross_origin', 'Requests from other sites are refused'))
    }
  }
  if (Number(getRequestHeader(event, 'content-length') ?? 0) > MAX_API_BODY_BYTES) {
    return refuse(event, new AppError(413, 'payload_too_large', 'The request is too large'))
  }
})

/** End the request with the API's usual error body, `{ error: { code, message } }`. */
function refuse(event: H3Event, error: AppError) {
  setResponseStatus(event, error.status)
  return { error: { code: error.code, message: error.message } }
}
