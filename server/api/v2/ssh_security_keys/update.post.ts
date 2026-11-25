import { z } from 'zod'
import { renameSshSecurityKey } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKey } from '@certifly/core/ssh-presenters'

/** Rename one of the signed-in person's security keys. Refused for API keys. */
export default defineRpc(z.object({ id: z.uuid(), name: z.string().min(1).max(100) }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentSshSecurityKey(actor, await renameSshSecurityKey(useContext(), actor, body.id, body.name)) }
})
