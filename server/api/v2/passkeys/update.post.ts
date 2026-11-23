import { z } from 'zod'
import { renamePasskey } from '@certifly/core/auth/passkeys'

/** Rename one of the signed-in person's passkeys. */
export default defineRpc(z.object({ id: z.uuid(), name: z.string().min(1).max(100) }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: await renamePasskey(useContext(), actor, body.id, body.name) }
})
