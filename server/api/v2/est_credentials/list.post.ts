import { z } from 'zod'
import { listEstCredentials } from '@certifly/core/est'
import { presentEstCredential } from '@certifly/core/presenters'

/**
 * List EST credentials
 *
 * The named credentials of one template's EST endpoints, newest first, revoked ones included.
 * They hold no password: it is only shown when a credential is created. Every signed-in role
 * that can read the template may list.
 */
export default defineRpc(z.object({ template_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const rows = await listEstCredentials(useContext(), actor, body.template_id)
  return { data: rows.map((row) => presentEstCredential(actor, row)) }
})
