import { z } from 'zod'
import { addGroupMember } from '@certifly/core/groups'

/** Add a person to a group by hand. A membership that came from the identity provider becomes a manual one. Admins, also with API keys. */
export default defineRpc(z.object({ group_id: z.uuid(), user_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await addGroupMember(useContext(), actor, body.group_id, body.user_id)
  return { data: { added: true } }
})
