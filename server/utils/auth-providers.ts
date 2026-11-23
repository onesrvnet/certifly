import type { H3Event } from 'h3'
import * as client from 'openid-client'
import type { SigninProfile } from '@certifly/core/auth/provision'

/** Why an external sign-in was refused; shown on the sign-in page as `?error=`. */
export class ProviderError extends Error {
  constructor(readonly code: string) {
    super(code)
  }
}

export const OIDC_ID = 'oidc'

export const oidcEnabled = () => {
  const config = env()
  return Boolean(config.OIDC_ISSUER && config.OIDC_CLIENT_ID && config.OIDC_CLIENT_SECRET)
}

let configuration: Promise<client.Configuration> | undefined

/** The provider's discovery document, fetched once per process and retried after a failure. */
export function oidcConfiguration() {
  const config = env()
  configuration ??= client.discovery(new URL(config.OIDC_ISSUER!), config.OIDC_CLIENT_ID!, config.OIDC_CLIENT_SECRET!).catch((error) => {
    configuration = undefined
    throw error
  })
  return configuration
}

/**
 * The verified identity behind an ID token. The provider must vouch for the email address
 * (`email_verified: true`): anyone who can register an unverified address at the provider
 * could otherwise sign in as its owner.
 */
export function oidcProfile(claims: client.IDToken | undefined): SigninProfile {
  if (!claims) throw new ProviderError('oidc_failed')
  const email = typeof claims.email === 'string' ? claims.email : undefined
  if (!email || claims.email_verified !== true) throw new ProviderError('oidc_email')
  return {
    email,
    name: typeof claims.name === 'string' ? claims.name : undefined,
    identity: { provider: OIDC_ID, subject: claims.sub },
    groups: oidcGroups(claims),
  }
}

/**
 * The group names in the claim `OIDC_GROUPS_CLAIM` names, or undefined when it is not configured
 * or the ID token has no such claim (then memberships are left as they are). A claim that is
 * present but not a list of strings counts as an empty list.
 */
export function oidcGroups(claims: client.IDToken): string[] | undefined {
  const name = env().OIDC_GROUPS_CLAIM
  if (!name || !(name in claims)) return undefined
  const value = (claims as Record<string, unknown>)[name]
  const list = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[,\s]+/) : []
  return list.filter((g): g is string => typeof g === 'string' && g.length > 0)
}

interface AuthFlow {
  codeVerifier?: string
  state?: string
  /** The setup token the person presented, for the first sign-in on an empty instance. */
  setupToken?: string
  /** Set when the flow re-authenticates a signed-in session instead of signing in. */
  reauth?: {
    session_id: string
    /** App page to return to afterwards. */
    return_to: string
    /** When the redirect to the provider started (epoch ms); its sign-in must be newer. */
    started_at: number
  }
}

/** Short-lived state of a running provider sign-in. */
export function authFlowSession(event: H3Event) {
  const config = env()
  return useSession<AuthFlow>(event, {
    name: 'certifly_auth_flow',
    password: config.SECRET_KEY,
    maxAge: 10 * 60,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.URL.startsWith('https://'),
      path: '/auth',
    },
  })
}

/** Where the provider sends people back; register this as the redirect URI. */
export const oidcCallbackUrl = () => new URL('/auth/oidc/callback', env().URL).toString()

/**
 * A path inside this app to send someone back to, or `/`. Anything that could point at
 * another site (`//evil.example`, `/\\evil.example`, a full URL) falls back to `/`.
 */
export function safeReturnPath(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/'
  // Resolving against a dummy origin catches anything that would leave it.
  const url = new URL(value, 'http://certifly.invalid')
  return url.origin === 'http://certifly.invalid' ? `${url.pathname}${url.search}${url.hash}` : '/'
}

/** `path` with `?name=value` added, keeping its other query parameters. */
export function withQuery(path: string, name: string, value: string): string {
  const url = new URL(path, 'http://certifly.invalid')
  url.searchParams.set(name, value)
  return `${url.pathname}${url.search}${url.hash}`
}
