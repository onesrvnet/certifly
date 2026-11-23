import type { H3Event } from 'h3'
import * as client from 'openid-client'
import { confirmIdentity, provisionUser } from '@certifly/core/auth/provision'
import { assertFreshAuthTime, reauthenticateSession } from '@certifly/core/auth/sessions'
import { AppError } from '@certifly/core/errors'
import { syncProviderGroups } from '@certifly/core/groups'

/** How old the provider's sign-in may be when its answer arrives, for a re-authentication. */
const REAUTH_MAX_AGE_SECONDS = 5 * 60

/**
 * Complete an OpenID Connect flow. For a sign-in: verify the response, find or create the
 * account (the provider must vouch for the email address), start a session and go to the app;
 * a refusal returns to the sign-in page with an error code. For a re-authentication: check
 * that the provider signed in the same person just now, mark the session re-authenticated and
 * return to the page it started from (with `?reauth_error=` when that failed).
 */
export default defineEventHandler(async (event) => {
  if (!oidcEnabled()) throw createError({ statusCode: 404 })
  await limit(event, 'signinVerify', clientIp(event))
  const flow = await authFlowSession(event)
  const { codeVerifier, state, setupToken, reauth } = flow.data
  await flow.clear()

  if (reauth) return finishReauth(event, { codeVerifier, state, reauth })

  const fail = (code: string) => sendRedirect(event, `/login?error=${code}`)
  if (!codeVerifier || !state) return fail('oidc_state')

  try {
    const tokens = await client.authorizationCodeGrant(await oidcConfiguration(), new URL(getRequestURL(event).search, oidcCallbackUrl()), {
      pkceCodeVerifier: codeVerifier,
      expectedState: state,
    })
    const profile = oidcProfile(tokens.claims())
    const user = await provisionUser(useContext(), profile, { method: 'oidc', setup_token: setupToken })
    // A failing group sync must not lock anyone out; memberships stay as they were until the next sign-in.
    await syncProviderGroups(useContext(), user, profile.groups).catch((error) => logServerError('[auth] syncing provider groups failed', error, { provider: OIDC_ID }))
    await signIn(event, user, 'oidc')
    return sendRedirect(event, '/')
  } catch (error) {
    if (error instanceof ProviderError || error instanceof AppError) return fail(error.code)
    logServerError('[auth] oidc sign-in failed', error, { provider: OIDC_ID })
    return fail('oidc_failed')
  }
})

async function finishReauth(
  event: H3Event,
  flow: { codeVerifier?: string; state?: string; reauth: { session_id: string; return_to: string; started_at: number } },
) {
  const returnTo = safeReturnPath(flow.reauth.return_to)
  const fail = (code: string) => sendRedirect(event, withQuery(returnTo, 'reauth_error', code))
  // The flow must finish in the session that started it.
  const auth = await getAuth(event)
  if (!auth?.session || auth.session.id !== flow.reauth.session_id) return sendRedirect(event, `/login?redirect=${encodeURIComponent(returnTo)}`)
  if (!flow.codeVerifier || !flow.state) return fail('oidc_state')

  try {
    const tokens = await client.authorizationCodeGrant(await oidcConfiguration(), new URL(getRequestURL(event).search, oidcCallbackUrl()), {
      pkceCodeVerifier: flow.codeVerifier,
      expectedState: flow.state,
      // Makes the library insist on `auth_time`, which a provider must send when asked for `max_age`.
      maxAge: REAUTH_MAX_AGE_SECONDS,
    })
    const claims = tokens.claims()
    assertFreshAuthTime(claims?.auth_time, new Date(flow.reauth.started_at))
    const ctx = useContext()
    await confirmIdentity(ctx, auth.actor, oidcProfile(claims))
    await reauthenticateSession(ctx, auth.actor, auth.session.id, 'oidc')
    return sendRedirect(event, withQuery(returnTo, 'reauth', 'done'))
  } catch (error) {
    if (error instanceof ProviderError || error instanceof AppError) return fail(error.code)
    // The library's own check of `auth_time` against `maxAge`.
    if (error instanceof client.ClientError && error.code === 'OAUTH_JWT_TIMESTAMP_CHECK_FAILED') return fail('reauth_stale')
    logServerError('[auth] oidc re-authentication failed', error, { provider: OIDC_ID })
    return fail('oidc_failed')
  }
}
