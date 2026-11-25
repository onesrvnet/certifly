import { z } from 'zod'
import { signUserCertificate } from '@certifly/core/ssh-certificates'
import { presentSignedUserCertificate } from '@certifly/core/ssh-presenters'

/**
 * Sign a user certificate
 *
 * Signs the `public_key` (an authorized_keys line) for `host_group_id`, with the logins the
 * person holds there. The lifetime is `ttl_seconds` (the host group's default when left out,
 * `ttl_too_long` above its maximum). Where the host group requires a security key, it must be
 * one the person registered (`ssh_security_key_enrollments.start`). Errors: `ssh_no_access`,
 * `ssh_key_policy` (a security key, or an attested one, is needed), `ssh_key_not_registered`,
 * `ssh_key_revoked`, `ssh_key_type`. Operators and admins may sign for another person with
 * `for_user_id`; that person's own access rules and registered keys apply. Works with a command-line session,
 * an API key or a browser session. `serial` is a decimal string.
 */
export default defineRpc(
  z.object({
    host_group_id: z.uuid(),
    public_key: sshPublicKeyLine,
    ttl_seconds: z.number().int().optional(),
    for_user_id: z.uuid().optional(),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    await limit(event, 'issue', actor.cli_session_id ? `cli:${actor.cli_session_id}` : actor.api_key_id ? `key:${actor.api_key_id}` : `user:${actor.id}`)
    return { data: presentSignedUserCertificate(await signUserCertificate(useContext(), actor, body)) }
  },
)
