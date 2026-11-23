import { z } from 'zod'
import { listAlertChannels } from '@certifly/core/alerts'
import { presentAlertChannel } from '@certifly/core/presenters'

/**
 * List alert channels
 *
 * Email and webhook channels alphabetically. Webhook secrets are never included, only
 * `has_secret`. Admins only. Pass `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(z.object({ ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listAlertChannels(useContext(), actor, body)
  return { data: rows.map((row) => presentAlertChannel(actor, row.channel)), next_cursor }
})
