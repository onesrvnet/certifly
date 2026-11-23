import { z } from 'zod'
import { revokeOwnSession } from '@certifly/core/auth/sessions'

/**
 * Delete a session
 *
 * Without `id`, signs out the current session. With `id`, ends one of the signed-in
 * person's other sessions; a session of somebody else is reported as not found.
 */
export default defineRpc(z.object({ id: z.uuid().optional() }), async (event, body) => {
  const auth = await getAuth(event)
  if (!body.id || body.id === auth?.session?.id) {
    await signOut(event)
    return { data: { deleted: true } }
  }
  const { actor } = await requireSession(event)
  await revokeOwnSession(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
