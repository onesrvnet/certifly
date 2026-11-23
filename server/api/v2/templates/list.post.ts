import { z } from 'zod'
import { presentTemplate } from '@certifly/core/presenters'
import { listTemplates } from '@certifly/core/templates'

/**
 * List templates
 *
 * Templates alphabetically, each with the CA it is bound to. Filter by `ca_id` or `status`
 * (`active`, `archived`). Each carries `bound_to_root` and `max_ttl_exceeds_ca` for warnings.
 * Every signed-in role may list. Pass `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(
  z.object({ ca_id: z.uuid().optional(), status: z.enum(['active', 'archived']).optional(), ...paginationSchema }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor } = await listTemplates(useContext(), actor, body)
    return { data: rows.map((row) => presentTemplate(actor, row)), next_cursor }
  },
)
