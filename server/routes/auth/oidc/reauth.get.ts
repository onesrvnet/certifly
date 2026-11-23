import * as client from 'openid-client'

/**
 * Start re-authenticating the signed-in session with the configured OpenID Connect provider,
 * for an instance (or a person) without email or passkeys. The provider is asked to sign the
 * person in again however recently they did (`prompt=login`, `max_age=0`); the callback then
 * checks that it was this person and that the sign-in is fresh, and returns to `?return_to=`.
 */
export default defineEventHandler(async (event) => {
  if (!oidcEnabled()) throw createError({ statusCode: 404 })
  const returnTo = safeReturnPath(getQuery(event).return_to)
  const auth = await getAuth(event)
  if (!auth?.session) return sendRedirect(event, `/login?redirect=${encodeURIComponent(returnTo)}`)
  await limit(event, 'signinRequest', `reauth:${auth.user.id}`)

  const codeVerifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  const flow = await authFlowSession(event)
  await flow.update({ codeVerifier, state, setupToken: undefined, reauth: { session_id: auth.session.id, return_to: returnTo, started_at: Date.now() } })

  const url = client.buildAuthorizationUrl(await oidcConfiguration(), {
    redirect_uri: oidcCallbackUrl(),
    scope: env().OIDC_SCOPES,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
    prompt: 'login',
    max_age: '0',
  })
  return sendRedirect(event, url.toString())
})
