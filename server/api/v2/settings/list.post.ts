import { z } from 'zod'
import { listSettings } from '@certifly/core/settings'

/** List the instance settings as a key/value record (admins). */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: await listSettings(useContext(), actor) }
})
