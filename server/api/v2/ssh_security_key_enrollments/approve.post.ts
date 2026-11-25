import { z } from 'zod'
import { approveSecurityKeyEnrollment } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKeyEnrollment } from '@certifly/core/ssh-presenters'

/**
 * Approve a security key registration
 *
 * Registers the uploaded key for the signed-in person; host groups that require a security key
 * sign it from then on. Needs the person's own browser session, recently re-authenticated
 * (`reauth_required`). Errors: `ssh_key_already_registered`, `ssh_key_enrollment_expired`.
 */
export default defineRpc(z.object({ enrollment_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireSession(event)
  return { data: presentSshSecurityKeyEnrollment(await approveSecurityKeyEnrollment(useContext(), actor, body.enrollment_id)) }
})
