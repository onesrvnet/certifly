import { z } from 'zod'
import { getCliLogin } from '@certifly/core/cli-auth'
import { presentCliLogin } from '@certifly/core/ssh-presenters'

/**
 * Get a pending command-line sign-in
 *
 * For the confirm screen: the machine, the code and when it expires. Needs a browser session.
 * Unknown, expired or spent logins are `cli_login_expired`.
 */
export default defineRpc(z.object({ login_id: z.uuid() }), async (event, body) => {
  await requireSession(event)
  return { data: presentCliLogin(await getCliLogin(useContext(), body.login_id)) }
})
