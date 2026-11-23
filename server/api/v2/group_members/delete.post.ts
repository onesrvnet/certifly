import { z } from 'zod'
import { removeGroupMember } from '@certifly/core/groups'

/** Remove a manually added member from a group. Members that come from the identity provider are refused (`member_from_provider`). Admins, also with API keys. */
export default defineRpc(z.object({ group_id: z.uuid(), user_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await removeGroupMember(useContext(), actor, body.group_id, body.user_id)
  return { data: { deleted: true } }
})
