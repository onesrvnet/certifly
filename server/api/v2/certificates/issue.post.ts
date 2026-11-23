import { z } from 'zod'
import { getCertificate, issueCertificate } from '@certifly/core/certificates'
import { presentIssueResult } from '@certifly/core/presenters'

/**
 * Issue a certificate
 *
 * Issues a leaf certificate with the template `template_id`. Send either `csr` (PKCS#10, PEM; its
 * signature is verified and its key must be an algorithm the template allows) or `keygen`
 * (`{ algorithm, format: "pem" | "pkcs12", pkcs12_password }`, if the template allows it; the
 * password needs at least 12 characters). `sans` default to the CSR's; each must match the
 * template (`san_not_allowed`, `wildcard_not_allowed`, `san_type_not_allowed`, every one in
 * `error.details.violations`) and the CA's name constraints (`name_constraints_violation`).
 * `ttl_seconds` defaults to the template's and may not exceed its maximum
 * (`ttl_exceeds_maximum`). Key usage and extended key usage come from the template, never from
 * the CSR. `tag_ids` sets the certificate's tags exactly (`[]` for none); without it, the
 * template's default tags are copied. The answer holds the certificate with its chain and bundle, `not_after_clamped` when
 * the CA ends sooner, and for keygen `private_key`, this once: certifly does not keep it. Sent
 * with `Cache-Control: no-store`. Operators and admins, also with API keys.
 */
export default defineRpc(
  z.object({
    template_id: z.uuid(),
    csr: z.string().min(1).max(64_000).optional(),
    keygen: keygenSchema.optional(),
    common_name: z.string().trim().min(1).max(64).optional(),
    sans: z.array(sanSchema).max(100).optional(),
    ttl_seconds: z.number().int().positive().optional(),
    tag_ids: tagIdsSchema.optional(),
  }),
  async (event, body) => {
    noStore(event)
    const auth = await requireAuth(event)
    await limit(event, 'issue', auth.apiKeyId ? `key:${auth.apiKeyId}` : `user:${auth.user.id}`)
    const ctx = useContext()
    const result = await issueCertificate(ctx, auth.actor, { ...body, source: requestSource(auth.apiKeyId) })
    return { data: presentIssueResult(auth.actor, result, await getCertificate(ctx, auth.actor, result.certificate.id)) }
  },
)
