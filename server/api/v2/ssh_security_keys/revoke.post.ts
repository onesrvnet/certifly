import { z } from 'zod'
import { revokeSshSecurityKey } from '@certifly/core/ssh-security-keys'
import { presentSshSecurityKey } from '@certifly/core/ssh-presenters'

/**
 * Revoke a security key
 *
 * certifly stops signing the key, and every valid certificate for it goes on its CA's
 * revocation list at once. People revoke their own keys, admins anyone's. Needs a recently
 * re-authenticated browser session (`reauth_required`).
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentSshSecurityKey(actor, await revokeSshSecurityKey(useContext(), actor, body.id)) }
})
