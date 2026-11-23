import { z } from 'zod'
import { listReachableHosts } from '@certifly/core/ssh-access'
import { presentReachableHost } from '@certifly/core/ssh-presenters'

/**
 * List the hosts the signed-in person can reach
 *
 * Hosts in the host groups where the person has at least one login, with the logins they hold
 * there. `limit` goes up to 500. Works with a command-line session, an API key or a browser
 * session.
 */
export default defineRpc(z.object({ cursor: z.string().max(1000).optional(), limit: z.number().int().min(1).max(500).default(100) }), async (event, body) => {
  const { user } = await requireAuth(event)
  const { rows, next_cursor } = await listReachableHosts(useContext(), user, body)
  return { data: rows.map(presentReachableHost), next_cursor }
})
