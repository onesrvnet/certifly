import { z } from 'zod'
import { listCertificateGroups } from '@certifly/core/certificates'
import { presentCertificateGroup } from '@certifly/core/presenters'

/**
 * List certificate groups
 *
 * The certificates matching the same filters as `certificates.list`, counted per `group_by`:
 * `tag`, `template`, `ca` or `status`. Each group has a `key` (an id, a status, `untagged` or
 * `imported`), a `label` (the tag, template or CA name; null for `untagged`, `imported` and
 * statuses), the tag's `color` (null otherwise), `count`, `expiring_within_30_days` (active and
 * running out within 30 days) and `filter`: merged into the same filters, `certificates.list`
 * returns exactly that group's certificates. A certificate with two tags counts in both tag
 * groups; `untagged` comes last. Imported certificates have no CA or template and form the
 * `imported` group, last. Only groups with certificates are listed. Every signed-in role may list.
 */
export default defineRpc(
  z.object({ group_by: z.enum(['tag', 'template', 'ca', 'status']), ...certificateFilterSchema }),
  async (event, { expiring_before, ...body }) => {
    const { actor } = await requireAuth(event)
    const groups = await listCertificateGroups(useContext(), actor, { ...body, expiring_before: expiring_before ? new Date(expiring_before) : undefined })
    return { data: groups.map(presentCertificateGroup) }
  },
)
