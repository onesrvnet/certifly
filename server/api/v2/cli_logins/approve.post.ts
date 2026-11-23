import { z } from 'zod'
import { approveCliLogin } from '@certifly/core/cli-auth'
import { presentCliLogin } from '@certifly/core/ssh-presenters'

/**
 * Approve a command-line sign-in
 *
 * The signed-in person lets the waiting CLI act as them for 12 hours. Needs a browser session:
 * API keys and command-line tokens are refused, so a leaked token cannot mint more tokens.
 */
export default defineRpc(z.object({ login_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireSession(event)
  return { data: presentCliLogin(await approveCliLogin(useContext(), actor, body.login_id)) }
})
