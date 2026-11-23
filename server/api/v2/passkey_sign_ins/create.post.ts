import { z } from 'zod'
import { passkeyAuthenticationOptions } from '@certifly/core/auth/passkeys'

/** Step 1 of signing in with a passkey: options for navigator.credentials.get. */
export default defineRpc(z.object({}), async (event) => {
  await limit(event, 'signinRequest', clientIp(event))
  const options = await passkeyAuthenticationOptions(useContext())
  await rememberChallenge(event, 'authenticate', options.challenge)
  return { data: options }
})
