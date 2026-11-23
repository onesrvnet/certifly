import { z } from 'zod'
import { getSshCa } from '@certifly/core/ssh-cas'
import { presentSshCa } from '@certifly/core/ssh-presenters'

/**
 * Get an SSH certificate authority
 *
 * The CA with its public key (an authorized_keys line), fingerprint and public URLs. Every
 * signed-in role may read.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentSshCa(actor, await getSshCa(useContext(), actor, body.id)) }
})
