import { z } from 'zod'
import { listCliSessions } from '@certifly/core/cli-auth'
import { presentCliSession } from '@certifly/core/ssh-presenters'

/** List the signed-in person's own live command-line sessions. Browser session or API key. */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: (await listCliSessions(useContext(), actor)).map((row) => presentCliSession(row, row.id === actor.cli_session_id)) }
})
