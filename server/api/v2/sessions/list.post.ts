import { z } from 'zod'
import { listUserSessions } from '@certifly/core/auth/sessions'
import { presentSession } from '@certifly/core/presenters'

/** List the signed-in person's own sessions (browsers and devices), most recently active first. */
export default defineRpc(z.object({}), async (event) => {
  const { actor, session } = await requireSession(event)
  const rows = await listUserSessions(useContext(), actor)
  return { data: rows.map((row) => presentSession(row, session.id)) }
})
