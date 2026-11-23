import { z } from 'zod'
import { revokeCliSession } from '@certifly/core/cli-auth'

/**
 * Sign a command-line session out
 *
 * A command-line token with no `id` ends itself. A person with a browser session or API key
 * names one of their own sessions with `id`; other people's sessions are not found.
 */
export default defineRpc(z.object({ id: z.uuid().optional() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  await revokeCliSession(useContext(), actor, body.id)
  return { data: { deleted: true } }
})
