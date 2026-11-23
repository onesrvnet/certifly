import { z } from 'zod'
import { getSshHostGroup } from '@certifly/core/ssh-host-groups'
import { presentSshHostGroup } from '@certifly/core/ssh-presenters'

/**
 * Get an SSH host group
 *
 * Its settings: host name patterns, user certificate lifetimes, extensions, forced command,
 * source addresses, key policy and host certificate lifetime. Operators and admins.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentSshHostGroup(actor, await getSshHostGroup(useContext(), actor, body.id)) }
})
