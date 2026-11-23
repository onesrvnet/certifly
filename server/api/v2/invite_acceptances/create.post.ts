import { z } from 'zod'
import { acceptInvite } from '@certifly/core/invites'

/**
 * Accept an invite
 *
 * Public. Exchanges the token from the invite link for an account with the invited role,
 * optionally with the person's own name, and starts a session.
 */
export default defineRpc(z.object({ token: z.string().min(1).max(200), name: z.string().trim().min(1).max(100).optional() }), async (event, body) => {
  await limit(event, 'signinVerify', clientIp(event))
  const user = await acceptInvite(useContext(), body.token, { name: body.name })
  await signIn(event, user, 'email')
  return { data: { signed_in: true } }
})
