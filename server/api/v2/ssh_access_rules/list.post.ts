import { z } from 'zod'
import { listSshAccessRules } from '@certifly/core/ssh-access'
import { presentSshAccessRule } from '@certifly/core/ssh-presenters'

/**
 * List SSH access rules
 *
 * Which group may log in to which host group, as whom. Filter by `host_group_id` or `group_id`.
 * Admins only.
 */
export default defineRpc(z.object({ host_group_id: z.uuid().optional(), group_id: z.uuid().optional(), ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listSshAccessRules(useContext(), actor, body)
  return { data: rows.map((row) => presentSshAccessRule(actor, row)), next_cursor }
})
