import { z } from 'zod'
import { denySecurityKeyEnrollment } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKeyEnrollment } from '@certifly/core/ssh-presenters'

/** Deny a security key registration; the CLI's next poll gets `ssh_key_enrollment_denied`. Needs a browser session. */
export default defineRpc(z.object({ enrollment_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireSession(event)
  return { data: presentSshSecurityKeyEnrollment(await denySecurityKeyEnrollment(useContext(), actor, body.enrollment_id)) }
})
