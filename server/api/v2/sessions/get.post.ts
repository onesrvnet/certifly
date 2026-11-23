import { z } from 'zod'
import { presentInstance, presentSession, presentUser } from '@certifly/core/presenters'

/**
 * Get the current session
 *
 * The signed-in person, what they may do on the instance, and (for a cookie session) the
 * session itself, including whether it was re-authenticated recently. A 401 means signed out.
 */
export default defineRpc(z.object({}), async (event) => {
  const { user, session, actor } = await requireAuth(event)
  return {
    data: {
      user: presentUser(actor, user),
      instance: presentInstance(actor),
      session: session ? presentSession(session, session.id) : null,
    },
  }
})
