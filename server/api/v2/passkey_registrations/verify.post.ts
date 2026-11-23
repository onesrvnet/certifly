import { z } from 'zod'
import { type RegistrationResponseJSON, registerPasskey } from '@certifly/core/auth/passkeys'

/**
 * Step 2 of adding a passkey: verify the browser's response and store it. A passkey that is
 * already registered is refused (`passkey_exists`). Open while setup is pending; the first
 * passkey finishes it.
 */
export default defineRpc(
  z.object({ response: z.record(z.string(), z.unknown()), name: z.string().max(100).optional() }),
  async (event, body) => {
    const { actor } = await requireSession(event)
    const challenge = await takeChallenge(event, 'register')
    const passkey = await registerPasskey(useContext(), actor, {
      response: body.response as unknown as RegistrationResponseJSON,
      challenge,
      origin: requestOrigin(),
      name: body.name,
    })
    return { data: passkey }
  },
)
