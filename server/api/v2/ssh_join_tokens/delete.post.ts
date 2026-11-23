import { z } from 'zod'
import { deleteJoinToken } from '@certifly/core/ssh-hosts'

/** Delete a join token, so it can no longer be used. Admins only, from an interactive session. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteJoinToken(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
