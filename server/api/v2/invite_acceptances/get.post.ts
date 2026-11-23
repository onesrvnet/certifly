import { z } from 'zod'
import { previewInvite } from '@certifly/core/invites'

/**
 * Look at an invite
 *
 * Public. Shows what the token from an invite link offers (the address, the role and who sent
 * it) so the person can check it before accepting. Does not accept or change the invite.
 */
export default defineRpc(z.object({ token: z.string().min(1).max(200) }), async (event, body) => {
  await limit(event, 'signinVerify', clientIp(event))
  const invite = await previewInvite(useContext(), body.token)
  return { data: { ...invite, expires_at: invite.expires_at.toISOString() } }
})
