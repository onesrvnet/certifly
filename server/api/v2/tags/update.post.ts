import { z } from 'zod'
import { presentTag } from '@certifly/core/presenters'
import { getTag, updateTag } from '@certifly/core/tags'

/**
 * Update a tag
 *
 * Renames or recolours a tag; every certificate and template carrying it shows the change.
 * Same rules as create. Admins only, from a recently re-authenticated session; API keys are refused.
 */
export default defineRpc(z.object({ id: z.uuid(), name: z.string().max(200).optional(), color: z.string().max(20).optional() }), async (event, { id, ...body }) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await updateTag(ctx, actor, id, body as Parameters<typeof updateTag>[3])
  return { data: presentTag(actor, await getTag(ctx, actor, id)) }
})
