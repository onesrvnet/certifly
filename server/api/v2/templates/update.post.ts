import { z } from 'zod'
import { presentTemplate } from '@certifly/core/presenters'
import { getTemplate, updateTemplate } from '@certifly/core/templates'

/**
 * Update a template
 *
 * Changes the given fields and validates the result as a whole, against the CA it ends up bound
 * to (`ca_id` moves it). The slug never changes, and archived templates cannot be changed
 * (`template_archived`). `tag_ids` replaces the default tags. Certificates already issued are not
 * touched, their tags included. Admins only, from a
 * recently re-authenticated session; API keys are refused.
 */
export default defineRpc(
  z.object({
    id: z.uuid(),
    name: z.string().trim().min(1).max(100).optional(),
    description: z.string().max(1000).optional(),
    ca_id: z.uuid().optional(),
    ...templateSettingsSchema,
    tag_ids: tagIdsSchema.optional(),
  }),
  async (event, { id, ...body }) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    await updateTemplate(ctx, actor, id, body)
    return { data: presentTemplate(actor, await getTemplate(ctx, actor, id)) }
  },
)
