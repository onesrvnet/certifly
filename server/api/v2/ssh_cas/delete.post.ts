import { z } from 'zod'
import { deleteSshCa } from '@certifly/core/ssh-cas'

/**
 * Delete an SSH certificate authority
 *
 * Only a CA that nothing uses: no host groups and no certificates it signed (`ssh_ca_in_use`).
 * Admins only, from an interactive session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteSshCa(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
