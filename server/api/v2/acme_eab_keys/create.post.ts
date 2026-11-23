import { z } from 'zod'
import { createAcmeEabKey } from '@certifly/core/acme'
import { presentAcmeEabKey } from '@certifly/core/presenters'

/**
 * Create an ACME binding key
 *
 * A named key a new ACME account must be bound to (external account binding, RFC 8555 §7.3.4).
 * The response has the `kid` and the generated `hmac_key` (base64url); the HMAC key is only in
 * this response, which is sent with `Cache-Control: no-store`. Admins only, from a recently
 * re-authenticated session (`reauth_required`); API keys never qualify.
 */
export default defineRpc(z.object({ template_id: z.uuid(), name: z.string().trim().min(1).max(100) }), async (event, body) => {
  noStore(event)
  const { actor } = await requireAuth(event)
  const { key, hmac_key } = await createAcmeEabKey(useContext(), actor, body)
  return { data: { ...presentAcmeEabKey(actor, key), hmac_key } }
})
