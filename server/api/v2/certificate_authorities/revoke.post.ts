import { z } from 'zod'
import { getCertificateAuthority, revokeCertificateAuthority } from '@certifly/core/cas'
import { presentCertificateAuthorityDetail } from '@certifly/core/presenters'
import { CA_REVOCATION_REASONS } from '@certifly/core/revocation'

/**
 * Revoke a certificate authority
 *
 * For an internal CA, puts every certificate its parent issued it on the parent's CRL (rebuilt
 * right away in the background) and disables it. An externally signed CA is marked compromised
 * instead: disabled, with the `reason` kept; revoke it at the outside issuer as well. A root
 * cannot be revoked (`ca_not_revocable`); disable it. Revoking a revoked CA changes nothing.
 * `reason` is an RFC 5280 reason: `unspecified`, `key_compromise`, `ca_compromise`,
 * `affiliation_changed`, `superseded` or `cessation_of_operation`. Admins only, from a recently
 * re-authenticated session.
 */
export default defineRpc(z.object({ id: z.uuid(), reason: z.enum(CA_REVOCATION_REASONS) }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await revokeCertificateAuthority(ctx, actor, body.id, { reason: body.reason })
  return { data: presentCertificateAuthorityDetail(actor, await getCertificateAuthority(ctx, actor, body.id)) }
})
