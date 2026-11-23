import { z } from 'zod'
import { revokeAcmeEabKey } from '@certifly/core/acme'
import { presentAcmeEabKey } from '@certifly/core/presenters'

/**
 * Revoke an ACME binding key
 *
 * No new account can be bound with it, and accounts bound to it stop working at once.
 * Certificates they already got stay valid. Revoking a revoked key changes nothing. Admins only,
 * from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentAcmeEabKey(actor, await revokeAcmeEabKey(useContext(), actor, body.id)) }
})
