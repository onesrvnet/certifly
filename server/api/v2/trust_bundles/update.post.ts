import { z } from 'zod'
import { presentTrustBundleDetail } from '@certifly/core/presenters'
import { TRAEFIK_CLIENT_AUTH_TYPES } from '@certifly/core/traefik'
import { updateTrustBundle } from '@certifly/core/trust-bundles'

/**
 * Update a trust bundle
 *
 * Changes the name, description, CAs (`ca_ids`, replacing the list) or `include_chain`; what is
 * left out stays. The `traefik_*` fields are the ones `create` takes. The slug, and so the public
 * URL, never changes. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(
  z.object({
    id: z.uuid(),
    name: z.string().max(100).optional(),
    description: z.string().max(1000).optional(),
    ca_ids: z.array(z.uuid()).min(1).max(50).optional(),
    include_chain: z.boolean().optional(),
    traefik_enabled: z.boolean().optional(),
    traefik_client_auth: z.boolean().optional(),
    traefik_client_auth_type: z.enum(TRAEFIK_CLIENT_AUTH_TYPES).optional(),
    traefik_tls_option_name: z.string().max(63).nullable().optional(),
    traefik_servers_transport: z.boolean().optional(),
    traefik_servers_transport_name: z.string().max(63).nullable().optional(),
    traefik_require_token: z.boolean().optional(),
  }),
  async (event, { id, ...body }) => {
    const { actor } = await requireAuth(event)
    return { data: presentTrustBundleDetail(actor, await updateTrustBundle(useContext(), actor, id, body)) }
  },
)
