import { z } from 'zod'
import { deleteSshHost } from '@certifly/core/ssh-hosts'

/** Remove an SSH host and revoke its valid certificates. Operators and admins, also with API keys. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteSshHost(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
