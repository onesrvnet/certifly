import { z } from 'zod'
import { consumeCode } from '@certifly/core/auth/email-tokens'
import { type AuthenticationResponseJSON, authenticatePasskey } from '@certifly/core/auth/passkeys'
import { reauthenticateSession } from '@certifly/core/auth/sessions'
import { AuthenticationError } from '@certifly/core/errors'

/**
 * Finish re-authenticating
 *
 * Step 2: checks the emailed code or the passkey response and marks the current session as
 * freshly re-authenticated, which opens sensitive actions for 10 minutes. A passkey of
 * another person does not count.
 */
export default defineRpc(
  z.union([
    z.object({ method: z.literal('email'), code: z.string().regex(/^\s*\d{6}\s*$/) }),
    z.object({ method: z.literal('passkey'), response: z.record(z.string(), z.unknown()) }),
  ]),
  async (event, body) => {
    const { user, actor, session } = await requireSession(event)
    const ctx = useContext()
    await limit(event, 'signinVerify', clientIp(event))
    if (body.method === 'email') {
      await consumeCode(ctx, { email: user.email, code: body.code })
    } else {
      const challenge = await takeChallenge(event, 'authenticate')
      const result = await authenticatePasskey(ctx, {
        response: body.response as unknown as AuthenticationResponseJSON,
        challenge,
        origin: requestOrigin(),
      })
      if (result.user.id !== user.id) throw new AuthenticationError('This passkey cannot be used to sign in', 'passkey_invalid')
    }
    const at = await reauthenticateSession(ctx, actor, session.id, body.method)
    return { data: { reauth_at: at.toISOString() } }
  },
)
