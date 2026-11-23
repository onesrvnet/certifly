import { z } from 'zod'
import { createCertificateAuthority, getCertificateAuthority } from '@certifly/core/cas'
import { presentCertificateAuthorityDetail } from '@certifly/core/presenters'

const constraintSet = z
  .object({
    dns: z.array(z.string().trim().max(253)).max(100).default([]),
    ip: z.array(z.string().trim().max(64)).max(100).default([]),
    email: z.array(z.string().trim().max(320)).max(100).default([]),
  })
  .default({ dns: [], ip: [], email: [] })

const common = {
  name: z.string().trim().min(1).max(100),
  slug: z.string().min(1).max(64),
  description: z.string().max(1000).optional(),
  subject: z
    .array(z.object({ type: z.enum(['CN', 'O', 'OU', 'C', 'ST', 'L', 'E', 'DC', 'serialNumber']), value: z.string().trim().min(1).max(256) }))
    .min(1)
    .max(20),
  key_algorithm: z.enum(['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096']).default('ecdsa-p384'),
  path_length: z.number().int().min(0).max(16).nullable(),
  name_constraints: z.object({ permitted: constraintSet, excluded: constraintSet }).nullable().optional(),
  crl_validity_hours: z.number().int().min(1).max(8784).optional(),
  crl_overlap_hours: z.number().int().min(0).max(8783).optional(),
}
const validity_days = z.number().int().min(1).max(36_500)

/**
 * Create a certificate authority
 *
 * `signing` picks the kind: `self_signed` makes a root and signs it at once; `internal` has the
 * CA signed by the active parent `parent_ca_id`; `external` generates the key and a CSR and leaves
 * the CA `pending_certificate` until its certificate is imported. `name_constraints` (permitted
 * and excluded DNS suffixes, IP CIDRs, email domains) are optional for a root and required
 * otherwise, and an internal CA's must lie inside its parent's. pathLen and validity must fit
 * inside the parent's. Refusals carry the crypto layer's code, e.g. `name_constraints_not_subset`,
 * `path_length_exceeded`, `validity_not_nested`. Admins only, from a recently re-authenticated
 * session (`reauth_required`); API keys are refused.
 */
export default defineRpc(
  z.discriminatedUnion('signing', [
    z.object({ signing: z.literal('self_signed'), validity_days, ...common }),
    z.object({ signing: z.literal('internal'), parent_ca_id: z.uuid(), validity_days, ...common }),
    z.object({ signing: z.literal('external'), ...common }),
  ]),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const ca = await createCertificateAuthority(ctx, actor, body)
    return { data: presentCertificateAuthorityDetail(actor, await getCertificateAuthority(ctx, actor, ca.id)) }
  },
)
