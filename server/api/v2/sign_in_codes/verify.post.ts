import { z } from 'zod'
import { verifyEmailCode, verifyEmailToken } from '@certifly/core/auth/email'

/**
 * Sign in with a code or link
 *
 * Completes an email sign-in with the emailed code (together with the address) or the link
 * token, and starts a session. Creates the account when the rules allow it: the first
 * person on an empty instance, or someone with a pending invite.
 */
export default defineRpc(
  z.union([
    z.object({ token: z.string().min(1).max(200) }),
    z.object({ email: z.string().max(320), code: z.string().regex(/^\s*\d{6}\s*$/) }),
  ]),
  async (event, body) => {
    await limit(event, 'signinVerify', clientIp(event))
    const ctx = useContext()
    const user = 'token' in body ? await verifyEmailToken(ctx, body.token) : await verifyEmailCode(ctx, body)
    await signIn(event, user, 'email')
    return { data: { signed_in: true } }
  },
)
