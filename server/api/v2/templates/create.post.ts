import { z } from 'zod'
import { presentTemplate } from '@certifly/core/presenters'
import { createTemplate, getTemplate } from '@certifly/core/templates'

/**
 * Create a template
 *
 * Binds a set of issuance rules to an active CA. `preset` (`webserver_tls`, `mtls_server`,
 * `mtls_client`, `server_client`) fills every setting the body leaves out; without it, every
 * setting is required. `allowed_dns` takes domain patterns (`api.example.com`, `*.example.com`
 * for one label, `**.example.com` for any depth) and `allowed_ips` CIDRs; both must lie inside
 * the CA's name constraints (`template_outside_name_constraints`, with each problem in
 * `error.details.problems`). Binding to a root CA is allowed; the answer flags it with
 * `bound_to_root`. `tag_ids` sets the default tags copied onto each certificate it issues. Admins only, from a recently re-authenticated session (`reauth_required`);
 * API keys are refused.
 */
export default defineRpc(
  z.object({
    name: z.string().trim().min(1).max(100),
    slug: z.string().min(1).max(64),
    description: z.string().max(1000).optional(),
    ca_id: z.uuid(),
    preset: z.enum(['webserver_tls', 'mtls_server', 'mtls_client', 'server_client']).optional(),
    ...templateSettingsSchema,
    tag_ids: tagIdsSchema.optional(),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const template = await createTemplate(ctx, actor, body)
    return { data: presentTemplate(actor, await getTemplate(ctx, actor, template.id)) }
  },
)
