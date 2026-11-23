import { z } from 'zod'
import { updateAlertChannel } from '@certifly/core/alerts'
import { presentAlertChannelResult } from '@certifly/core/presenters'

/**
 * Update an alert channel
 *
 * Changes the name, the recipients (email) or the URL (webhook). `rotate_secret: true` gives a
 * webhook a new secret, returned once as `secret`; the old one stops working at once. Sent with
 * `Cache-Control: no-store`. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(
  z.object({
    id: z.uuid(),
    name: z.string().max(100).optional(),
    recipients: z.array(z.string().max(254)).min(1).max(20).optional(),
    url: z.string().max(2048).optional(),
    rotate_secret: z.boolean().optional(),
  }),
  async (event, { id, ...body }) => {
    noStore(event)
    const { actor } = await requireAuth(event)
    return { data: presentAlertChannelResult(actor, await updateAlertChannel(useContext(), actor, id, body)) }
  },
)
