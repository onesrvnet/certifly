import type { IncomingMessage } from 'node:http'
import type { H3Event } from 'h3'

/** Largest JSON API request body. Protocol routes (ACME, EST) pass tighter limits of their own. */
export const MAX_API_BODY_BYTES = 1024 * 1024

/** Where h3 (and Nuxt's request helpers) look for a body that was read already. */
const RAW_BODY = Symbol.for('h3RawBody')

/**
 * Read the request body, at most `max` bytes. The body is counted while it arrives, so an
 * oversized or chunked body is cut off instead of being buffered whole. The bytes are left in
 * h3's cache, so `readBody` afterwards parses them without reading again. Resolves to null when
 * the body is too large, to undefined when there is none.
 */
export async function readCappedBody(event: H3Event, max: number): Promise<Buffer | null | undefined> {
  const req = event.node.req as IncomingMessage & { [RAW_BODY]?: Promise<Buffer> }
  const declared = Number(getRequestHeader(event, 'content-length') ?? 0)
  if (declared > max) return null
  if (req[RAW_BODY]) return req[RAW_BODY]
  // Requests made inside the server (Nuxt's SSR calls to the API) carry their body in memory and
  // may repeat the page request's content-length; their stream never emits anything. h3 reads
  // those, and they come from the server itself, so only the size is checked.
  const inMemory = '__unenv__' in req || 'body' in req || 'rawBody' in req || !!(event as { _requestBody?: unknown })._requestBody || !!event.web?.request
  if (inMemory) {
    const body = await readRawBody(event, false)
    return body && body.length > max ? null : body
  }
  if (!declared && !/\bchunked\b/i.test(getRequestHeader(event, 'transfer-encoding') ?? '')) return undefined
  const tooLarge = Symbol('too large')
  const read = new Promise<Buffer | typeof tooLarge>((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req
      .on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > max) {
          req.pause()
          resolve(tooLarge)
          return
        }
        chunks.push(chunk)
      })
      .on('end', () => resolve(Buffer.concat(chunks)))
      .on('error', reject)
  })
  const body = await read
  if (body === tooLarge) return null
  req[RAW_BODY] = Promise.resolve(body)
  return body
}
