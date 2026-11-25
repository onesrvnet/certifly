import { z } from 'zod'
import { listSshSecurityKeys } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKey } from '@certifly/core/ssh-presenters'

/**
 * List security keys
 *
 * The signed-in person's registered YubiKeys, active ones first, with the number of valid
 * certificates for each. Admins may pass `user_id` for someone else's. Refused for API keys.
 */
export default defineRpc(z.object({ user_id: z.uuid().optional() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: (await listSshSecurityKeys(useContext(), actor, body)).map((key) => presentSshSecurityKey(actor, key)) }
})
