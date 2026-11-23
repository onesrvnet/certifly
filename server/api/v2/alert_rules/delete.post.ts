import { z } from 'zod'
import { deleteAlertRule } from '@certifly/core/alerts'

/**
 * Delete an alert rule
 *
 * Its delivery history stays. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteAlertRule(useContext(), actor, body.id)
  return { data: { id: body.id, deleted: true } }
})
