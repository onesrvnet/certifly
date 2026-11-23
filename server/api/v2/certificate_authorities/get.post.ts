import { z } from 'zod'
import { getCertificateAuthority } from '@certifly/core/cas'
import { presentCertificateAuthorityDetail } from '@certifly/core/presenters'

/**
 * Get a certificate authority
 *
 * The CA with its decoded active certificate, every certificate version, the issuer chain, the
 * CRL number and dates, its parent and children, and its public URLs. Downloads come with it as
 * PEM text: `active_certificate.pem`, `chain_pem`, and `pending_csr.pem` while a CSR waits for a
 * certificate. Every signed-in role may read.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentCertificateAuthorityDetail(actor, await getCertificateAuthority(useContext(), actor, body.id)) }
})
