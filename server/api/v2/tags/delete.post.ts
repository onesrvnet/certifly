import { z } from 'zod'
import { deleteTag } from '@certifly/core/tags'

/**
 * Delete a tag
 *
 * Removes the tag from every certificate and template, and answers how many lost it
 * (`removed_from_certificates`, `removed_from_templates`). Admins only, from a recently
 * re-authenticated session; API keys are refused.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, { id }) => {
  const { actor } = await requireAuth(event)
  const { removed_from_certificates, removed_from_templates } = await deleteTag(useContext(), actor, id)
  return { data: { removed_from_certificates, removed_from_templates } }
})
