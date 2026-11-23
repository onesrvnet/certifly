import { z } from 'zod'
import { sendAlertTest } from '@certifly/core/alerts'
import { presentAlertDelivery } from '@certifly/core/presenters'

/**
 * Send a test alert
 *
 * Sends a test alert through a channel right away and returns the delivery: `status` is `sent`,
 * or `failed` with the reason in `last_error`. Tests are kept in the delivery history but never
 * retried. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(z.object({ channel_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const delivery = await sendAlertTest(useContext(), actor, body.channel_id)
  return { data: presentAlertDelivery(actor, { delivery, rule: null, channel: null }) }
})
