import { z } from 'zod'
import { presentTrustBundleDetail } from '@certifly/core/presenters'
import { TRAEFIK_CLIENT_AUTH_TYPES } from '@certifly/core/traefik'
import { createTrustBundle } from '@certifly/core/trust-bundles'

/**
 * Create a trust bundle
 *
 * A named set of CA certificates, served publicly at `/api/pki/bundle/<slug>.pem`. `ca_ids` are
 * the CAs, in order; with `include_chain`, each CA's issuers up to the root are added too. For
 * each CA the bundle holds the newest valid certificate of every key that still has one. The slug
 * is part of the public URL and cannot change later. The `traefik_*` fields optionally serve the
 * bundle as Traefik dynamic configuration at `/api/pki/bundle/<slug>/traefik.yml`: `traefik_enabled`
 * turns it on, `traefik_client_auth` (with `traefik_client_auth_type`) adds a TLS option that
 * verifies client certificates against the bundle, `traefik_servers_transport` adds a servers
 * transport that trusts backends signed by it, both named by `traefik_tls_option_name` and
 * `traefik_servers_transport_name` (null or blank for the defaults), and `traefik_require_token`
 * makes the endpoint ask for the bundle's own token (`tb_…`), which is generated when the
 * requirement is turned on and returned once, in `traefik_token`. At least one of the two parts must be on when enabled.
 * Admins only, from a recently re-authenticated session.
 */
export default defineRpc(
  z.object({
    name: z.string().max(100),
    slug: z.string().max(64),
    description: z.string().max(1000).optional(),
    ca_ids: z.array(z.uuid()).min(1).max(50),
    include_chain: z.boolean().optional(),
    traefik_enabled: z.boolean().optional(),
    traefik_client_auth: z.boolean().optional(),
    traefik_client_auth_type: z.enum(TRAEFIK_CLIENT_AUTH_TYPES).optional(),
    traefik_tls_option_name: z.string().max(63).nullable().optional(),
    traefik_servers_transport: z.boolean().optional(),
    traefik_servers_transport_name: z.string().max(63).nullable().optional(),
    traefik_require_token: z.boolean().optional(),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    return { data: presentTrustBundleDetail(actor, await createTrustBundle(useContext(), actor, body)) }
  },
)
