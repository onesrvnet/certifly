import { z } from 'zod'
import { deleteTrustBundle } from '@certifly/core/trust-bundles'

/**
 * Delete a trust bundle
 *
 * Its public URL stops working. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteTrustBundle(useContext(), actor, body.id)
  return { data: { id: body.id, deleted: true } }
})
