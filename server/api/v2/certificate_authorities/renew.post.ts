import { z } from 'zod'
import { getCertificateAuthority, renewCertificateAuthority } from '@certifly/core/cas'
import { presentCertificateAuthorityDetail } from '@certifly/core/presenters'

/**
 * Renew a certificate authority
 *
 * A root or internal CA gets a new certificate version for the same key, valid for
 * `validity_days` (required for them); an internal CA is signed again by its parent, which must
 * be active. An externally signed CA gets a new key and a fresh CSR instead (`pending_csr`), to
 * be signed outside and imported. The CRL is published again. Admins only, from a recently
 * re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid(), validity_days: z.number().int().min(1).max(36_500).optional() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await renewCertificateAuthority(ctx, actor, body.id, { validity_days: body.validity_days })
  return { data: presentCertificateAuthorityDetail(actor, await getCertificateAuthority(ctx, actor, body.id)) }
})
