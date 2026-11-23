import { z } from 'zod'
import { getCertificate } from '@certifly/core/certificates'
import { presentCertificateDetail } from '@certifly/core/presenters'
import { LEAF_REVOCATION_REASONS, revokeCertificate } from '@certifly/core/revocation'

/**
 * Revoke a certificate
 *
 * Revokes a leaf certificate with an RFC 5280 `reason` (`unspecified`, `key_compromise`,
 * `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`,
 * `privilege_withdrawn`). It goes on the CRL of the CA key that signed it, which is rebuilt
 * right away in the background, and stays there until it expires. Revoking a revoked
 * certificate changes nothing. Imported and expired certificates cannot be revoked
 * (`certificate_not_revocable`). Operators and admins, also with API keys.
 */
export default defineRpc(z.object({ id: z.uuid(), reason: z.enum(LEAF_REVOCATION_REASONS) }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await revokeCertificate(ctx, actor, body.id, { reason: body.reason })
  return { data: presentCertificateDetail(actor, await getCertificate(ctx, actor, body.id)) }
})
