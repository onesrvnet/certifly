import { z } from 'zod'
import { getSecurityKeyEnrollment } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKeyEnrollment } from '@certifly/core/ssh-presenters'

/**
 * Get a security key registration
 *
 * For the approval page: the machine, the code, the key and its model. Needs a browser session;
 * only the person's own uploaded registrations are found (`ssh_key_enrollment_expired` otherwise).
 */
export default defineRpc(z.object({ enrollment_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireSession(event)
  return { data: presentSshSecurityKeyEnrollment(await getSecurityKeyEnrollment(useContext(), actor, body.enrollment_id)) }
})
