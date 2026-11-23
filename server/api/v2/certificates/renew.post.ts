import { z } from 'zod'
import { getCertificate, renewCertificate } from '@certifly/core/certificates'
import { presentIssueResult } from '@certifly/core/presenters'

/**
 * Renew a certificate
 *
 * Issues a new certificate with the same template, subject, SANs and tags, checked against the
 * template as it is now. Send a new `csr`, or `keygen` for a new key pair; with neither, the
 * stored CSR is used again (a certificate whose key certifly generated needs `keygen` or a CSR).
 * The old certificate becomes `superseded` and points at the new one (`superseded_by_id`). The
 * answer is shaped like `certificates.issue`, private key included for keygen, and sent with
 * `Cache-Control: no-store`. Operators and admins, also with API keys.
 */
export default defineRpc(
  z.object({
    id: z.uuid(),
    csr: z.string().min(1).max(64_000).optional(),
    keygen: keygenSchema.optional(),
    ttl_seconds: z.number().int().positive().optional(),
  }),
  async (event, { id, ...body }) => {
    noStore(event)
    const auth = await requireAuth(event)
    await limit(event, 'issue', auth.apiKeyId ? `key:${auth.apiKeyId}` : `user:${auth.user.id}`)
    const ctx = useContext()
    const result = await renewCertificate(ctx, auth.actor, id, { ...body, source: requestSource(auth.apiKeyId) })
    return { data: presentIssueResult(auth.actor, result, await getCertificate(ctx, auth.actor, result.certificate.id)) }
  },
)
