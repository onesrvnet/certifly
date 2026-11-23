import { z } from 'zod'
import { signUserCertificate } from '@certifly/core/ssh-certificates'
import { presentSignedUserCertificate } from '@certifly/core/ssh-presenters'

/**
 * Sign a user certificate
 *
 * Signs the `public_key` (an authorized_keys line) for `host_group_id`, with the logins the
 * person holds there. The lifetime is `ttl_seconds` (the host group's default when left out,
 * `ttl_too_long` above its maximum). Errors: `ssh_no_access`, `ssh_key_policy` (a security key
 * or an attestation is needed), `ssh_attestation_invalid`, `ssh_key_type`. `attestation` is the
 * base64 of the file `ssh-keygen -O write-attestation=` wrote, `attestation_challenge` the base64
 * of the 32 bytes given to `-O challenge=`. Operators and admins may sign for another person
 * with `for_user_id`; that person's own access rules apply. Works with a command-line session,
 * an API key or a browser session. `serial` is a decimal string.
 */
export default defineRpc(
  z.object({
    host_group_id: z.uuid(),
    public_key: sshPublicKeyLine,
    ttl_seconds: z.number().int().optional(),
    attestation: z.string().max(65_536).optional(),
    attestation_challenge: z.string().max(200).optional(),
    for_user_id: z.uuid().optional(),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    await limit(event, 'issue', actor.cli_session_id ? `cli:${actor.cli_session_id}` : actor.api_key_id ? `key:${actor.api_key_id}` : `user:${actor.id}`)
    return { data: presentSignedUserCertificate(await signUserCertificate(useContext(), actor, body)) }
  },
)
