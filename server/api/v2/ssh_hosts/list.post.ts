import { z } from 'zod'
import { listSshHosts } from '@certifly/core/ssh-hosts'
import { presentSshHost } from '@certifly/core/ssh-presenters'

/**
 * List SSH hosts
 *
 * The host registry by name, each with its host group and current host certificate. Filter by
 * `host_group_id` or `query` (part of a name or host name). Operators and admins.
 */
export default defineRpc(z.object({ host_group_id: z.uuid().optional(), query: z.string().max(200).optional(), ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listSshHosts(useContext(), actor, body)
  return { data: rows.map((row) => presentSshHost(actor, row)), next_cursor }
})
