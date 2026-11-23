import { z } from 'zod'
import { presentTemplate } from '@certifly/core/presenters'
import { getTemplate } from '@certifly/core/templates'

/**
 * Get a template
 *
 * One template with its rules and the CA it is bound to. Every signed-in role may read.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentTemplate(actor, await getTemplate(useContext(), actor, body.id)) }
})
