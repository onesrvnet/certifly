import { z } from 'zod'
import { listUsers } from '@certifly/core/users'
import { presentListedUser } from '@certifly/core/presenters'

/**
 * List people
 *
 * Admins see everyone, filtered by `query` (name or email), `role` and `include_deactivated`.
 * Operators see every active person, filtered by `query`, as `{id, name, email, username}` only
 * (their own row is complete). Anyone else sees only themselves. Pass `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(
  z.object({
    query: z.string().max(100).optional(),
    role: z.enum(['admin', 'operator', 'viewer']).optional(),
    include_deactivated: z.boolean().optional(),
    ...paginationSchema,
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor } = await listUsers(useContext(), actor, body)
    return { data: rows.map((row) => presentListedUser(actor, row)), next_cursor }
  },
)
