import { z } from 'zod'
import { presentTrustBundleDetail } from '@certifly/core/presenters'
import { regenerateTraefikToken } from '@certifly/core/trust-bundles'

/**
 * Regenerate a trust bundle's Traefik token
 *
 * Replaces the token that Traefik sends as `Authorization: Bearer` to fetch the bundle's
 * configuration. The old token stops working at once. The new one is returned once, in
 * `traefik_token`, and never again. Only for bundles with `traefik_require_token`. Admins only,
 * from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentTrustBundleDetail(actor, await regenerateTraefikToken(useContext(), actor, body.id)) }
})
