import { z } from 'zod'
import { listPasskeys } from '@certifly/core/auth/passkeys'

/** List passkeys: the signed-in person's own. */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: await listPasskeys(useContext(), actor) }
})
