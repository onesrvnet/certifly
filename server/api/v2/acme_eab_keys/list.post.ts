import { z } from 'zod'
import { listAcmeEabKeys } from '@certifly/core/acme'
import { presentAcmeEabKey } from '@certifly/core/presenters'

/**
 * List ACME binding keys
 *
 * The external account binding keys of one template's ACME directory, newest first, revoked ones
 * included. They hold no HMAC key: it is only shown when a key is created. Every signed-in role
 * that can read the template may list.
 */
export default defineRpc(z.object({ template_id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const rows = await listAcmeEabKeys(useContext(), actor, body.template_id)
  return { data: rows.map((row) => presentAcmeEabKey(actor, row)) }
})
