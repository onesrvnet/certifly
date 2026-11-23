import { z } from 'zod'
import { disableCertificateAuthority, getCertificateAuthority } from '@certifly/core/cas'
import { presentCertificateAuthorityDetail } from '@certifly/core/presenters'

/**
 * Disable a certificate authority
 *
 * Takes the CA out of service: it signs no certificates, subordinate CAs or renewals any more.
 * Its certificate, chain and CRL stay published at the public URLs, and the CRL keeps being
 * rebuilt, so what it issued can still be checked. Disabling a disabled CA changes nothing.
 * Admins only, from a recently re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await disableCertificateAuthority(ctx, actor, body.id)
  return { data: presentCertificateAuthorityDetail(actor, await getCertificateAuthority(ctx, actor, body.id)) }
})
