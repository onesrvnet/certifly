import type { H3Event } from 'h3'
import { getApiKeyUser } from '@certifly/core/api-keys'
import { createSession, getSessionUser, revokeSession, SESSION_TTL_MS } from '@certifly/core/auth/sessions'
import { CLI_TOKEN_PREFIX, getCliSessionUser } from '@certifly/core/cli-auth'
import { AuthenticationError, AuthorizationError } from '@certifly/core/errors'
import type { Actor } from '@certifly/core/policies'

interface SessionData {
  sessionId?: string
}

const SESSION_COOKIE = 'certifly_session'

function cookieSession(event: H3Event) {
  const config = env()
  return useSession<SessionData>(event, {
    name: SESSION_COOKIE,
    password: config.SECRET_KEY,
    maxAge: SESSION_TTL_MS / 1000,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.URL.startsWith('https://'),
      path: '/',
    },
  })
}

/** How someone proved who they are. */
export type SigninMethod = 'email' | 'passkey' | 'oidc' | 'setup_token'

/**
 * The only endpoints a command-line session token (`cfc_…`) may call. Everything else refuses
 * it before it reaches a handler, whatever the role of the person behind it.
 */
const CLI_ENDPOINTS: ReadonlySet<string> = new Set([
  '/api/v2/ssh_access/get',
  '/api/v2/ssh_hosts/reachable',
  '/api/v2/ssh_user_certificates/sign',
  '/api/v2/cli_sessions/delete',
])

/** Start a session for the user and set the session cookie. */
export async function signIn(event: H3Event, user: { id: string }, method: SigninMethod) {
  const session = await createSession(useContext(), user.id, {
    user_agent: getRequestHeader(event, 'user-agent'),
    ip_address: requestIp(event) ?? undefined,
    method,
  })
  const cookie = await cookieSession(event)
  await cookie.update({ sessionId: session.id })
}

/** End the current session and clear its cookie. */
export async function signOut(event: H3Event) {
  const cookie = await cookieSession(event)
  if (cookie.data.sessionId) await revokeSession(useContext(), cookie.data.sessionId)
  await cookie.clear()
}

type SessionAuth = NonNullable<Awaited<ReturnType<typeof getSessionUser>>>
export interface Auth {
  user: SessionAuth['user']
  /** The cookie session; null for API keys and command-line sessions. */
  session: SessionAuth['session'] | null
  apiKeyId?: string
  /** Set when the request came with a command-line session token. */
  cliSessionId?: string
  /** Who is acting, as core's permission checks and audit log expect. */
  actor: Actor
}

async function authOf(event: H3Event, user: Auth['user'], session: Auth['session'], apiKeyId?: string, cliSessionId?: string): Promise<Auth> {
  return {
    user,
    session,
    apiKeyId,
    cliSessionId,
    actor: {
      id: user.id,
      role: user.role,
      kind: cliSessionId ? 'cli' : apiKeyId ? 'api_key' : 'session',
      api_key_id: apiKeyId,
      cli_session_id: cliSessionId,
      ip: requestIp(event),
      // Core's step-up checks read this; API keys and command-line sessions have no browser session, so they never pass them.
      reauth_at: apiKeyId || cliSessionId ? null : (session?.reauth_at ?? null),
    },
  }
}

/**
 * The signed-in user, or null. Accepts an API key as `Authorization: Bearer <key>`,
 * otherwise the session cookie. Cached per request.
 */
export async function getAuth(event: H3Event): Promise<Auth | null> {
  if (event.context.auth !== undefined) return event.context.auth
  let auth: Auth | null = null
  const header = getRequestHeader(event, 'authorization')
  if (header?.startsWith('Bearer ')) {
    const token = header.slice('Bearer '.length).trim()
    if (token.startsWith(CLI_TOKEN_PREFIX)) {
      // The one place a command-line token is accepted, so no route can forget to refuse it.
      if (!CLI_ENDPOINTS.has(new URL(event.path, 'http://localhost').pathname)) {
        throw new AuthorizationError('This token can only be used by the command-line tool for signing in and certificates', 'cli_token_endpoint')
      }
      const result = await getCliSessionUser(useContext(), token)
      auth = result ? await authOf(event, result.user, null, undefined, result.session.id) : null
    } else {
      const result = await getApiKeyUser(useContext(), token)
      auth = result ? await authOf(event, result.user, null, result.key.id) : null
    }
  } else {
    const sessionId = (await cookieSession(event)).data.sessionId
    const found = sessionId ? await getSessionUser(useContext(), sessionId) : null
    auth = found ? await authOf(event, found.user, found.session) : null
  }
  event.context.auth = auth
  return auth
}

/** The signed-in user, session or API key; counts the request against the per-user API limit. */
export async function requireAuth(event: H3Event): Promise<Auth> {
  const auth = await getAuth(event)
  if (!auth) throw new AuthenticationError()
  if (!event.context.rateLimited) {
    event.context.rateLimited = true
    await limit(event, 'api', auth.apiKeyId ? `key:${auth.apiKeyId}` : auth.cliSessionId ? `cli:${auth.cliSessionId}` : `user:${auth.user.id}`)
  }
  return auth
}

/**
 * Like `requireAuth`, but refuses API keys, for what only makes sense in a browser (passkey
 * ceremonies, re-authentication, the list of signed-in devices). Core refuses API keys for
 * sensitive changes by itself (`assertStepUp`), whatever the route does.
 */
export async function requireSession(event: H3Event) {
  const auth = await requireAuth(event)
  if (!auth.session) throw new AuthorizationError('Use a signed-in session for this')
  return { ...auth, session: auth.session }
}

declare module 'h3' {
  interface H3EventContext {
    auth?: Auth | null
    /** Set once the per-user API limit was counted for this request. */
    rateLimited?: boolean
  }
}
