import { z } from 'zod'
import { createApiKey } from '@certifly/core/api-keys'
import { presentApiKey } from '@certifly/core/presenters'

/**
 * Create an API key
 *
 * A personal key that acts with its owner's role. The `secret` is only in this response.
 * Keys cannot create keys: a leaked key must not be able to mint more. Needs a recently
 * re-authenticated session (`reauth_required`).
 */
export default defineRpc(
  z.object({ name: z.string().min(1).max(100), expires_at: z.iso.datetime().nullable().optional() }),
  async (event, body) => {
    const { actor } = await requireSession(event)
    const { key, secret } = await createApiKey(useContext(), actor, {
      name: body.name,
      expires_at: body.expires_at ? new Date(body.expires_at) : null,
    })
    return { data: { ...presentApiKey(actor, key), secret } }
  },
)
