import { z } from 'zod'
import { listCertificates } from '@certifly/core/certificates'
import { presentCertificate } from '@certifly/core/presenters'

/**
 * List certificates
 *
 * Leaf certificates, each with its CA, template and tags. `sort` is `newest` (default), `expiry`
 * (soonest first) or `name` (common name, else the first SAN, else the subject); `order` is the
 * older name for it and is used only when `sort` is left out. Filter by `status` (`expired`
 * includes active certificates whose notAfter has passed), `ca_id`, `template_id`, `source`,
 * `imported` (true for inventory imports only, false for certificates certifly issued),
 * `expiring_before`, `tag_ids` (certificates carrying every one of them), `untagged` (true:
 * without tags, false: with at least one) and `query`, which matches part of the common name or
 * a SAN, or the start of the serial or fingerprint. Every signed-in role may list. Pass
 * `next_cursor` back as `cursor` for the next page.
 */
export default defineRpc(
  z.object({
    ...certificateFilterSchema,
    sort: z.enum(['newest', 'expiry', 'name']).optional(),
    order: z.enum(['newest', 'expiry']).optional(),
    ...paginationSchema,
  }),
  async (event, { expiring_before, order, sort, ...body }) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor } = await listCertificates(useContext(), actor, { ...body, sort: sort ?? order, expiring_before: expiring_before ? new Date(expiring_before) : undefined })
    return { data: rows.map((row) => presentCertificate(actor, row)), next_cursor }
  },
)
