import { z } from 'zod'
import { presentTag } from '@certifly/core/presenters'
import { createTag, getTag } from '@certifly/core/tags'

/**
 * Create a tag
 *
 * Adds a tag with a `name` (1 to 50 characters, unique regardless of case: `tag_name_taken`) and
 * a `color`: gray, blue, teal, green, yellow, orange, pink or violet (`invalid_tag_color`).
 * Admins only, from a recently re-authenticated session (`reauth_required`); API keys are refused.
 */
export default defineRpc(z.object({ name: z.string().max(200), color: z.string().max(20) }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  const tag = await createTag(ctx, actor, body as Parameters<typeof createTag>[2])
  return { data: presentTag(actor, await getTag(ctx, actor, tag.id)) }
})
