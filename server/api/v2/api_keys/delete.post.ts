import { z } from 'zod'
import { deleteApiKey } from '@certifly/core/api-keys'

/** Delete one of the signed-in person's API keys. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await deleteApiKey(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
