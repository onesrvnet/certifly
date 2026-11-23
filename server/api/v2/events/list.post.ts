import { z } from 'zod'
import { listEvents } from '@certifly/core/audit'
import { presentEvent } from '@certifly/core/presenters'

/**
 * List audit events
 *
 * The audit log, newest first, for every signed-in role. Filter by actor, event name,
 * subject and time range. Pass `next_cursor` back as `cursor` for older entries.
 */
export default defineRpc(
  z.object({
    actor_id: z.uuid().optional(),
    actor_type: z.enum(['user', 'api_key', 'acme', 'est', 'system']).optional(),
    name: z.string().max(100).optional(),
    subject_type: z.string().max(50).optional(),
    subject_id: z.uuid().optional(),
    from: z.iso.datetime().optional(),
    to: z.iso.datetime().optional(),
    ...paginationSchema,
  }),
  async (event, { from, to, ...body }) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor } = await listEvents(useContext(), actor, {
      ...body,
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
    })
    return { data: rows.map((row) => presentEvent(actor, row)), next_cursor }
  },
)
