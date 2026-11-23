import { z } from 'zod'
import { presentTrustBundle } from '@certifly/core/presenters'
import { listTrustBundles } from '@certifly/core/trust-bundles'

/**
 * List trust bundles
 *
 * Trust bundles alphabetically, each with its CAs and public PEM URL. Every signed-in role may
 * list. Pass `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(z.object({ ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listTrustBundles(useContext(), actor, body)
  return { data: rows.map((row) => presentTrustBundle(actor, row)), next_cursor }
})
