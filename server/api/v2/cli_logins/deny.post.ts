import { z } from 'zod'
import { denyCliLogin } from '@certifly/core/cli-auth'
import { presentCliLogin } from '@certifly/core/ssh-presenters'

/** Deny a command-line sign-in; the CLI's next poll gets `cli_login_denied`. Needs a browser session. */
export default defineRpc(z.object({ login_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireSession(event)
  return { data: presentCliLogin(await denyCliLogin(useContext(), actor, body.login_id)) }
})
