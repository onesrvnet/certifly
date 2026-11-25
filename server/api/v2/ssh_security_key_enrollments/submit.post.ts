import { z } from 'zod'
import { submitSecurityKeyEnrollment } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKeyEnrollment } from '@certifly/core/ssh-presenters'

/**
 * Upload the security key for a registration
 *
 * Only for the command-line session that started it. `public_key` is the `.pub` line of the key
 * made with the registration's challenge, `attestation` the base64 of the file
 * `ssh-keygen -O write-attestation=` wrote. A genuine YubiKey's attestation marks the key as
 * attested. The key waits for the person's approval in the browser. Errors: `ssh_key_type`,
 * `ssh_attestation_invalid`, `ssh_key_already_registered`, `ssh_key_enrollment_used`,
 * `ssh_key_enrollment_expired`.
 */
export default defineRpc(
  z.object({ enrollment_id: z.uuid(), public_key: sshPublicKeyLine, attestation: z.string().max(65_536).optional(), name: z.string().max(100).optional() }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    await limit(event, 'securityKeyEnrollment', `cli:${actor.cli_session_id ?? actor.id}`)
    return { data: presentSshSecurityKeyEnrollment(await submitSecurityKeyEnrollment(useContext(), actor, body)) }
  },
)
