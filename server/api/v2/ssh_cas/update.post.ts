import { z } from 'zod'
import { getSshCa, updateSshCa } from '@certifly/core/ssh-cas'
import { presentSshCa } from '@certifly/core/ssh-presenters'

/**
 * Update an SSH certificate authority
 *
 * Changes the name or description. The slug and the key never change. Admins only, from an
 * interactive session.
 */
export default defineRpc(z.object({ id: z.uuid(), name: z.string().max(200).optional(), description: z.string().max(1000).optional() }), async (event, { id, ...body }) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await updateSshCa(ctx, actor, id, body)
  return { data: presentSshCa(actor, await getSshCa(ctx, actor, id)) }
})
