import { z } from 'zod'
import { pollSecurityKeyEnrollment } from '@certifly/core/ssh-security-keys'
import { presentRegisteredSecurityKey } from '@certifly/core/ssh-presenters'

/**
 * Poll a security key registration
 *
 * Only for the command-line session that started it. Answers `{status: "pending"}` or
 * `{status: "approved", key}`. Errors: `ssh_key_enrollment_denied` (403),
 * `ssh_key_enrollment_expired` (410).
 */
export default defineRpc(z.object({ enrollment_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const result = await pollSecurityKeyEnrollment(useContext(), actor, body.enrollment_id)
  return result.status === 'pending' ? result : { status: result.status, key: presentRegisteredSecurityKey(result.key) }
})
