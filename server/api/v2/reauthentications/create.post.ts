import { z } from 'zod'
import { requestEmailReauth } from '@certifly/core/auth/email'
import { passkeyAuthenticationOptions } from '@certifly/core/auth/passkeys'

/**
 * Start re-authenticating
 *
 * Step 1 of proving who you are again for sensitive actions. With `method: "email"`, emails
 * a one-time code to the signed-in person's own address (not on an instance that cannot send
 * mail: `email_disabled`). With `method: "passkey"`, returns the options for
 * navigator.credentials.get. With the identity provider, go to `/auth/oidc/reauth` instead.
 * API keys cannot re-authenticate.
 */
export default defineRpc(z.object({ method: z.enum(['email', 'passkey']) }), async (event, body) => {
  const { user, actor } = await requireSession(event)
  const ctx = useContext()
  await limit(event, 'signinRequest', `reauth:${user.id}`)
  if (body.method === 'email') {
    await requestEmailReauth(ctx, actor)
    return { data: { method: 'email' as const } }
  }
  const options = await passkeyAuthenticationOptions(ctx)
  await rememberChallenge(event, 'authenticate', options.challenge)
  return { data: { method: 'passkey' as const, options } }
})
