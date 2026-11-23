import { z } from 'zod'
import { createHostChallenge } from '@certifly/core/ssh-hosts'

/**
 * Ask for a nonce to sign
 *
 * No sign-in. A host asks for a nonce, signs it with one of its registered SSH host keys and
 * sends the signature to `ssh_hosts.sync`. The nonce is valid for 5 minutes and works once.
 */
export default defineRpc(z.object({ host_id: z.uuid() }), async (event, body) => {
  await limit(event, 'sshHost', clientIp(event))
  const { nonce, expires_at } = await createHostChallenge(useContext(), body)
  return { nonce, expires_at: expires_at.toISOString() }
})
