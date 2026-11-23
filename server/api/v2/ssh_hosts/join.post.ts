import { z } from 'zod'
import { joinSshHost } from '@certifly/core/ssh-hosts'
import { presentHostSync } from '@certifly/core/ssh-presenters'

/**
 * Enrol a host with a join token
 *
 * No sign-in: the single-use `cfj_` token (`invalid_token` when unknown, spent or expired) is
 * the credential. `hostnames` must match the host group's patterns (`host_name_not_allowed`);
 * `public_keys` are the host's public keys from /etc/ssh/ssh_host_*_key.pub (`ssh_key_type`).
 * Answers with the host certificates, the CA public key, the revocation list URL and the
 * principals to install.
 */
export default defineRpc(
  z.object({ token: z.string().min(1).max(200), hostnames: z.array(z.string().max(253)).min(1).max(20), public_keys: z.array(sshPublicKeyLine).min(1).max(10) }),
  async (event, body) => {
    await limit(event, 'sshHost', clientIp(event))
    return { data: presentHostSync(await joinSshHost(useContext(), { ...body, ip: requestIp(event) })) }
  },
)
