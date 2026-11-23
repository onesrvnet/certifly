import { z } from 'zod'
import { getSshHost } from '@certifly/core/ssh-hosts'
import { presentSshHost } from '@certifly/core/ssh-presenters'

/** Get an SSH host with its names, public keys, last check-in and current certificate. Operators and admins. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentSshHost(actor, await getSshHost(useContext(), actor, body.id)) }
})
