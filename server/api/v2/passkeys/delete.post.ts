import { z } from 'zod'
import { deletePasskey } from '@certifly/core/auth/passkeys'

/** Delete one of the signed-in person's passkeys. Needs a recently re-authenticated session. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deletePasskey(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
