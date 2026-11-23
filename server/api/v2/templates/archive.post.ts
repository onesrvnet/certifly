import { z } from 'zod'
import { presentTemplate } from '@certifly/core/presenters'
import { archiveTemplate, getTemplate } from '@certifly/core/templates'

/**
 * Archive a template
 *
 * Nothing more is issued or renewed with it; certificates it issued stay valid. Archiving an
 * archived template changes nothing. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await archiveTemplate(ctx, actor, body.id)
  return { data: presentTemplate(actor, await getTemplate(ctx, actor, body.id)) }
})
