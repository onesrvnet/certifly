import { z } from 'zod'
import { listGroups } from '@certifly/core/groups'
import { presentGroup } from '@certifly/core/ssh-presenters'

/** List groups of people alphabetically, with their member counts. Admins only. */
export default defineRpc(z.object(paginationSchema), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listGroups(useContext(), actor, body)
  return { data: rows.map((row) => presentGroup(actor, row)), next_cursor }
})
