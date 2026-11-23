import { z } from 'zod'
import { deleteSshHostGroup } from '@certifly/core/ssh-host-groups'

/**
 * Delete an SSH host group
 *
 * Only when it has no hosts (`host_group_in_use`). Its access rules and join tokens go with it.
 * Admins, also with API keys.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteSshHostGroup(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
