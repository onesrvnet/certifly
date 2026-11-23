import { z } from 'zod'
import { presentTag } from '@certifly/core/presenters'
import { listTags } from '@certifly/core/tags'

/**
 * List tags
 *
 * Every tag alphabetically, with `certificate_count` and `template_count`. The list is small and
 * not paged. Every signed-in role may list, also with API keys.
 */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: (await listTags(useContext(), actor)).map((row) => presentTag(actor, row)) }
})
