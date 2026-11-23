import { z } from 'zod'
import { deleteGroup } from '@certifly/core/groups'

/** Delete a group. The access rules built on it go too. Admins, also with API keys. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteGroup(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
