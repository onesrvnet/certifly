import { z } from 'zod'
import { deleteSshAccessRule } from '@certifly/core/ssh-access'

/** Delete an SSH access rule. Certificates already signed stay valid until they expire. Admins, also with API keys. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteSshAccessRule(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
