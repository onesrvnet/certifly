import { z } from 'zod'
import { listGroupMembers } from '@certifly/core/groups'
import { presentGroupMember } from '@certifly/core/ssh-presenters'

/** List the members of a group by name, each with `source`: `manual` or `oidc` (from the identity provider). Admins only. */
export default defineRpc(z.object({ group_id: z.uuid(), ...paginationSchema }), async (event, { group_id, ...body }) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listGroupMembers(useContext(), actor, group_id, body)
  return { data: rows.map((row) => presentGroupMember(actor, row)), next_cursor }
})
