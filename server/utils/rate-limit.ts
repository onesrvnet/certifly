import type { H3Event } from 'h3'
import { hit } from '@certifly/core/rate-limit'

/**
 * Fixed-window rate limiting in Postgres (core `hit`), so limits hold across instances.
 * If the database fails the request is allowed and the error logged.
 */
export async function rateLimit(event: H3Event, bucket: string, key: string, limit: number, windowSeconds: number) {
  if (env().RATE_LIMITS_DISABLED) return
  const result = await hit(useContext(), `${bucket}:${key}`, limit, windowSeconds)
  setResponseHeaders(event, {
    'ratelimit-limit': String(limit),
    'ratelimit-remaining': String(result.remaining),
    'ratelimit-reset': String(result.reset),
  })
  if (!result.allowed) {
    setResponseHeader(event, 'retry-after', result.reset)
    throw createError({ statusCode: 429, statusMessage: 'Too many requests, try again later' })
  }
}

/**
 * Client IP. Behind a configured proxy (TRUST_PROXY=true) it is the last X-Forwarded-For entry,
 * the one that proxy added: a proxy that appends to the header keeps whatever the client sent
 * in front of it, so earlier entries are the client's own claim.
 */
export function requestIp(event: H3Event): string | null {
  if (env().TRUST_PROXY) {
    const forwarded = getRequestHeader(event, 'x-forwarded-for')?.split(',').at(-1)?.trim()
    if (forwarded) return forwarded
  }
  return getRequestIP(event) ?? null
}

export const clientIp = (event: H3Event) => requestIp(event) ?? 'unknown'

/** Named limits used across endpoints: [requests, window in seconds]. */
export const LIMITS = {
  signinRequest: [20, 3600],
  signinVerify: [10, 60],
  /** Every authenticated API request, per user or API key. Generous: the UI fans out reads. */
  api: [1200, 60],
  /** Public CRL and CA certificate downloads, per client address. Relying parties cache them. */
  pki: [600, 60],
  /** EST requests (RFC 7030), per client address. Devices enroll in bursts after a rollout. */
  est: [300, 60],
  /** ACME requests (RFC 8555), per client address. Clients poll orders and challenges, so this is generous. */
  acme: [600, 60],
  /**
   * Leaf issuance and renewal, per user or API key. Each one signs with a CA key and may generate
   * an RSA key, so a runaway script is stopped well before it hurts.
   */
  issue: [60, 60],
  /** Hosts joining, asking for challenges and syncing, and public SSH files, per client address. Hosts sync every 15 minutes; rollouts come in bursts. */
  sshHost: [300, 60],
  /** Command-line sign-ins starting and polling, per client address. */
  cliLogin: [120, 60],
} as const satisfies Record<string, readonly [number, number]>

export function limit(event: H3Event, name: keyof typeof LIMITS, key: string) {
  const [count, window] = LIMITS[name]
  return rateLimit(event, name, key, count, window)
}
