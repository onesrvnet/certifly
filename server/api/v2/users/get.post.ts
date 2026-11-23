import { z } from 'zod'
import { getUser } from '@certifly/core/users'
import { presentUser } from '@certifly/core/presenters'

/** Get a person. Admins may read anyone; everybody else only themselves. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentUser(actor, await getUser(useContext(), actor, body.id)) }
})
