import { z } from 'zod'
import { listJoinTokens } from '@certifly/core/ssh-hosts'
import { presentJoinToken } from '@certifly/core/ssh-presenters'

/** List host join tokens, newest first, without their secrets. Filter by `host_group_id` or `status` (`open`, `used`, `expired`). Admins only, from an interactive session. */
export default defineRpc(
  z.object({ host_group_id: z.uuid().optional(), status: z.enum(['open', 'used', 'expired']).optional(), ...paginationSchema }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor } = await listJoinTokens(useContext(), actor, body)
    return { data: rows.map((row) => presentJoinToken(actor, row)), next_cursor }
  },
)
