import { z } from 'zod'
import { listSshCas } from '@certifly/core/ssh-cas'
import { presentSshCa } from '@certifly/core/ssh-presenters'

/**
 * List SSH certificate authorities
 *
 * Every SSH CA alphabetically with its public key and the number of host groups that use it.
 * Every signed-in role may list. Pass `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(z.object(paginationSchema), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listSshCas(useContext(), actor, body)
  return { data: rows.map((row) => presentSshCa(actor, row)), next_cursor }
})
