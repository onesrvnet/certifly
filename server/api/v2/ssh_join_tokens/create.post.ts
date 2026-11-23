import { z } from 'zod'
import { createJoinToken } from '@certifly/core/ssh-hosts'
import { presentJoinToken } from '@certifly/core/ssh-presenters'

/**
 * Create a host join token
 *
 * A single-use `cfj_` token for enrolling a host into `host_group_id`; valid for `ttl_seconds`
 * (24 hours by default, at most 7 days). The `token` is in this answer only; certifly keeps a
 * hash. Admins only, from a recently re-authenticated session (`reauth_required`); API keys are
 * refused.
 */
export default defineRpc(z.object({ host_group_id: z.uuid(), label: z.string().max(100).optional(), ttl_seconds: z.number().int().optional() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { row, token } = await createJoinToken(useContext(), actor, body)
  return { data: presentJoinToken(actor, row, token) }
})
