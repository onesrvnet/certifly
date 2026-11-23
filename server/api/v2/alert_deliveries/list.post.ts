import { z } from 'zod'
import { listAlertDeliveries } from '@certifly/core/alerts'
import { presentAlertDelivery } from '@certifly/core/presenters'

/**
 * List alert deliveries
 *
 * Every alert sent or attempted, newest first: its rule and channel, what it was about
 * (`subject_label`), `status` (`pending`, `sent`, `retrying`, `failed`), `attempts` and
 * `last_error`. Filter by `status`, `rule_id` or `channel_id`. Operators and admins. Pass
 * `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(
  z.object({
    status: z.enum(['pending', 'sent', 'retrying', 'failed']).optional(),
    rule_id: z.uuid().optional(),
    channel_id: z.uuid().optional(),
    ...paginationSchema,
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor } = await listAlertDeliveries(useContext(), actor, body)
    return { data: rows.map((row) => presentAlertDelivery(actor, row)), next_cursor }
  },
)
