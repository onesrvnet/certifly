import { z } from 'zod'
import { getCertificate } from '@certifly/core/certificates'
import { presentCertificateDetail } from '@certifly/core/presenters'

/**
 * Get a certificate
 *
 * One leaf certificate with its decoded fields (`details`) and the downloads as PEM text: `pem`
 * (the certificate), `chain_pem` (the issuing CA up to the root) and `bundle_pem` (both, as
 * servers expect them). The DER form is the base64 body of `pem`. There is never a private key:
 * certifly does not keep one. Every signed-in role may read.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentCertificateDetail(actor, await getCertificate(useContext(), actor, body.id)) }
})
