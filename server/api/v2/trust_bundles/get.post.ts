import { z } from 'zod'
import { presentTrustBundleDetail } from '@certifly/core/presenters'
import { getTrustBundle } from '@certifly/core/trust-bundles'

/**
 * Get a trust bundle
 *
 * One trust bundle with its CAs and the certificates its public PEM holds right now
 * (`certificates`; `from_chain` marks those added by `include_chain`), and its Traefik settings
 * (`traefik_*`, the endpoint `traefik_url`, and `traefik_refs`, the names that other Traefik
 * configuration uses for the TLS option and servers transport). Every signed-in role may read.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentTrustBundleDetail(actor, await getTrustBundle(useContext(), actor, body.id)) }
})
