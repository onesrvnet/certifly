import { z } from 'zod'
import { listApiKeys } from '@certifly/core/api-keys'
import { presentApiKey } from '@certifly/core/presenters'

/** List the signed-in person's own API keys (never their secrets). */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: (await listApiKeys(useContext(), actor)).map((key) => presentApiKey(actor, key)) }
})
