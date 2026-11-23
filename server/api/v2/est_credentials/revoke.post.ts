import { z } from 'zod'
import { revokeEstCredential } from '@certifly/core/est'
import { presentEstCredential } from '@certifly/core/presenters'

/**
 * Revoke an EST credential
 *
 * The credential stops working at once. Certificates it already enrolled stay valid. Revoking a
 * revoked credential changes nothing. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentEstCredential(actor, await revokeEstCredential(useContext(), actor, body.id)) }
})
