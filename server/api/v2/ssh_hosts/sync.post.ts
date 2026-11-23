import { z } from 'zod'
import { syncSshHost } from '@certifly/core/ssh-hosts'
import { presentHostSync } from '@certifly/core/ssh-presenters'

/**
 * Sync a host
 *
 * No sign-in: `signature` is an armored SSHSIG over the `nonce` text (UTF-8, no newline) with
 * namespace `certifly-host@certifly`, made by one of the host's registered keys
 * (`host_not_verified` otherwise). `public_keys` is the host's current key list; a changed list
 * (key rotation) is accepted and the certificates of keys that left it are revoked. Certificates
 * with less than a third of their lifetime left are renewed.
 */
export default defineRpc(
  z.object({ host_id: z.uuid(), nonce: z.string().min(1).max(200), signature: z.string().min(1).max(16_384), public_keys: z.array(sshPublicKeyLine).min(1).max(10) }),
  async (event, body) => {
    await limit(event, 'sshHost', clientIp(event))
    return { data: presentHostSync(await syncSshHost(useContext(), { ...body, ip: requestIp(event) })) }
  },
)
