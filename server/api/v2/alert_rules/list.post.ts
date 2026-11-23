import { z } from 'zod'
import { listAlertRules } from '@certifly/core/alerts'
import { presentAlertRule } from '@certifly/core/presenters'

/**
 * List alert rules
 *
 * Alert rules alphabetically. Admins only. Pass `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(z.object({ ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listAlertRules(useContext(), actor, body)
  return { data: rows.map((row) => presentAlertRule(actor, row.rule)), next_cursor }
})
