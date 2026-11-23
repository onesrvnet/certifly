import { z } from 'zod'
import { deleteAlertChannel } from '@certifly/core/alerts'

/**
 * Delete an alert channel
 *
 * Removes it from every rule; its delivery history stays. Admins only, from a recently
 * re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteAlertChannel(useContext(), actor, body.id)
  return { data: { id: body.id, deleted: true } }
})
