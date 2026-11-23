import type { H3Event } from 'h3'

/** How long clients and caches may keep public CA material without asking again, at most. */
const MAX_AGE_SECONDS = 3600

/**
 * Send public PKI material (a CRL or CA certificate) with caching headers. `fresh_until` caps the
 * cache lifetime, so a CRL is never cached past its nextUpdate.
 */
export function sendPkiFile(
  event: H3Event,
  body: Uint8Array | string,
  options: { type: string; filename: string; modified: Date; fresh_until?: Date },
) {
  const remaining = options.fresh_until ? Math.floor((options.fresh_until.getTime() - Date.now()) / 1000) : MAX_AGE_SECONDS
  const maxAge = Math.max(0, Math.min(MAX_AGE_SECONDS, remaining))
  setResponseHeaders(event, {
    'content-type': options.type,
    'content-disposition': `attachment; filename="${options.filename}"`,
    'cache-control': `public, max-age=${maxAge}`,
    'last-modified': options.modified.toUTCString(),
    // Anyone may fetch these, from any origin: they are public by design.
    'access-control-allow-origin': '*',
  })
  return typeof body === 'string' ? body : Buffer.from(body.buffer, body.byteOffset, body.byteLength)
}

/** A CA slug from a URL, or null when it cannot be one (so it never reaches the database). */
export function caSlug(value: string | undefined): string | null {
  return value && /^[a-z0-9-]{1,64}$/.test(value) ? value : null
}

/** The slug in a file name such as `root-ca.crl`, or null when the name does not end that way. */
export function slugFromFile(name: string | undefined, extension: string): string | null {
  return name?.endsWith(extension) ? caSlug(name.slice(0, -extension.length)) : null
}

export function notFound() {
  return createError({ statusCode: 404, statusMessage: 'Not found' })
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** The CA key id in a file name such as `<key-id>.crl`, or null when it is not one. */
export function keyIdFromFile(name: string | undefined, extension: string): string | null {
  const id = name?.endsWith(extension) ? name.slice(0, -extension.length) : null
  return id && UUID.test(id) ? id : null
}
