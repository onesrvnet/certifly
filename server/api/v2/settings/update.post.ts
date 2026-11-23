import { z } from 'zod'
import { listSettings, setSetting } from '@certifly/core/settings'

/**
 * Update an instance setting
 *
 * Admins set one known key at a time. Only the key is written to the audit log. Needs a
 * recently re-authenticated session (`reauth_required`).
 */
export default defineRpc(
  z.discriminatedUnion('key', [z.object({ key: z.literal('instance.name'), value: z.string().trim().min(1).max(100) })]),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    await setSetting(ctx, actor, body.key, body.value)
    return { data: await listSettings(ctx, actor) }
  },
)
