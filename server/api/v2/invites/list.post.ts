import { z } from 'zod'
import { listInvites } from '@certifly/core/invites'
import { presentInvite } from '@certifly/core/presenters'

/** List invites (admins), newest first, optionally only `pending`, `accepted` or `expired` ones. */
export default defineRpc(z.object({ status: z.enum(['pending', 'accepted', 'expired', 'all']).optional(), ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listInvites(useContext(), actor, body)
  return { data: rows.map((row) => presentInvite(actor, row)), next_cursor }
})
