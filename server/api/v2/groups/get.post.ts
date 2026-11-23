import { z } from 'zod'
import { getGroup } from '@certifly/core/groups'
import { presentGroup } from '@certifly/core/ssh-presenters'

/** Get a group with its provider group names and member count. Admins only. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentGroup(actor, await getGroup(useContext(), actor, body.id)) }
})
