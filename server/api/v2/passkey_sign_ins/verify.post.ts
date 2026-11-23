import { z } from 'zod'
import { type AuthenticationResponseJSON, authenticatePasskey } from '@certifly/core/auth/passkeys'

/** Step 2 of signing in with a passkey: verify it and start a session. */
export default defineRpc(z.object({ response: z.record(z.string(), z.unknown()) }), async (event, body) => {
  await limit(event, 'signinVerify', clientIp(event))
  const challenge = await takeChallenge(event, 'authenticate')
  const { user } = await authenticatePasskey(useContext(), {
    response: body.response as unknown as AuthenticationResponseJSON,
    challenge,
    origin: requestOrigin(),
  })
  await signIn(event, user, 'passkey')
  return { data: { signed_in: true } }
})
