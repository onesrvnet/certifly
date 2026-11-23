import { z } from 'zod'
import { passkeyRegistrationOptions } from '@certifly/core/auth/passkeys'

/**
 * Step 1 of adding a passkey: options for navigator.credentials.create (via @simplewebauthn/browser).
 * Needs a recently re-authenticated session (`reauth_required`). Open while setup is pending:
 * adding the first passkey is how setup finishes, and the setup session counts as fresh.
 */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireSession(event)
  const options = await passkeyRegistrationOptions(useContext(), actor)
  await rememberChallenge(event, 'register', options.challenge)
  return { data: options }
})
