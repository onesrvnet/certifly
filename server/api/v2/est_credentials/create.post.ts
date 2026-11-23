import { z } from 'zod'
import { createEstCredential } from '@certifly/core/est'
import { presentEstCredential } from '@certifly/core/presenters'

/**
 * Create an EST credential
 *
 * A named username and password for a template's EST `simpleenroll` endpoint (HTTP basic
 * authentication). The generated `password` is only in this response and sent with
 * `Cache-Control: no-store`. Admins only, from a recently re-authenticated session
 * (`reauth_required`); API keys never qualify.
 */
export default defineRpc(z.object({ template_id: z.uuid(), name: z.string().trim().min(1).max(100) }), async (event, body) => {
  noStore(event)
  const { actor } = await requireAuth(event)
  const { credential, password } = await createEstCredential(useContext(), actor, body)
  return { data: { ...presentEstCredential(actor, credential), password } }
})
