import { z } from 'zod'
import { revokeInvite } from '@certifly/core/invites'

/** Revoke a pending invite (admins). The link stops working. Needs a recently re-authenticated session. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await revokeInvite(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
