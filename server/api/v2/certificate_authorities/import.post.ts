import { z } from 'zod'
import { getCertificateAuthority, importCaCertificate } from '@certifly/core/cas'
import { presentCertificateAuthorityDetail } from '@certifly/core/presenters'

/**
 * Import a CA certificate
 *
 * Installs the certificate an outside CA signed for an externally signed CA, with its issuer
 * chain up to the root (`chain`, PEM). It must match a key of this CA, keep the subject and the
 * requested pathLen, carry critical name constraints, be valid now and chain to a self-signed
 * root. A refusal lists every problem in `error.details.errors` (each `{ code, message }`); the
 * error code is the first problem's, e.g. `public_key_mismatch`. Importing again later adds a new
 * version (renewal by the root operator). Activates the CA and publishes its CRL. Admins only,
 * from a recently re-authenticated session.
 */
export default defineRpc(
  z.object({ id: z.uuid(), certificate: z.string().min(1).max(64_000), chain: z.string().max(256_000).default('') }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    await importCaCertificate(ctx, actor, body.id, { certificate: body.certificate, chain: body.chain })
    return { data: presentCertificateAuthorityDetail(actor, await getCertificateAuthority(ctx, actor, body.id)) }
  },
)
