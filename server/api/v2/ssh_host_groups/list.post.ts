import { z } from 'zod'
import { listSshHostGroups } from '@certifly/core/ssh-host-groups'
import { presentSshHostGroup } from '@certifly/core/ssh-presenters'

/**
 * List SSH host groups
 *
 * Host groups alphabetically, each with its SSH CA, rules and counts. Filter by `ssh_ca_id`.
 * Operators and admins may list.
 */
export default defineRpc(z.object({ ssh_ca_id: z.uuid().optional(), ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listSshHostGroups(useContext(), actor, body)
  return { data: rows.map((row) => presentSshHostGroup(actor, row)), next_cursor }
})
