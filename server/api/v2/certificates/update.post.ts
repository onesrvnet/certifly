import { z } from 'zod'
import { getCertificate, updateCertificate } from '@certifly/core/certificates'
import { presentCertificateDetail } from '@certifly/core/presenters'

/**
 * Update a certificate
 *
 * Replaces the certificate's tags with `tag_ids` (`[]` removes them all; an unknown id is
 * `tag_not_found`). Works on every certificate, imported ones too. The audit event lists the
 * tags added and removed. Operators and admins, also with API keys.
 */
export default defineRpc(z.object({ id: z.uuid(), tag_ids: tagIdsSchema }), async (event, { id, tag_ids }) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await updateCertificate(ctx, actor, id, { tag_ids })
  return { data: presentCertificateDetail(actor, await getCertificate(ctx, actor, id)) }
})
