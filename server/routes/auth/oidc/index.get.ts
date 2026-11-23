import * as client from 'openid-client'

/**
 * Start signing in with the configured OpenID Connect provider (authorization code flow
 * with PKCE). `?setup_token=` carries the setup token for the first sign-in on an empty instance.
 */
export default defineEventHandler(async (event) => {
  if (!oidcEnabled()) throw createError({ statusCode: 404 })
  await limit(event, 'signinRequest', clientIp(event))
  const query = getQuery(event)
  const setupToken = typeof query.setup_token === 'string' ? query.setup_token : undefined

  const codeVerifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  const flow = await authFlowSession(event)
  // Drop what an abandoned re-authentication may have left in the flow cookie.
  await flow.update({ codeVerifier, state, setupToken, reauth: undefined })

  const url = client.buildAuthorizationUrl(await oidcConfiguration(), {
    redirect_uri: oidcCallbackUrl(),
    scope: env().OIDC_SCOPES,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
  })
  return sendRedirect(event, url.toString())
})
