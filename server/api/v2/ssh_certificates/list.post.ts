import { z } from 'zod'
import { listSshCertificates } from '@certifly/core/ssh-certificates'
import { presentSshCertificate } from '@certifly/core/ssh-presenters'

/**
 * List SSH certificates
 *
 * User and host certificates, newest first. Filter by `kind`, `user_id`, `host_id`,
 * `host_group_id`, `ssh_ca_id` or `status` (`active`, `revoked`, `expired`), and search the key ID
 * and principals with `query`. `counts` holds how many match the filters other than `kind` and
 * `status`: `all`, `user`, `host` and `revoked`. Operators and admins see all; everyone else sees
 * only their own user certificates.
 */
export default defineRpc(
  z.object({
    kind: z.enum(['user', 'host']).optional(),
    user_id: z.uuid().optional(),
    host_id: z.uuid().optional(),
    host_group_id: z.uuid().optional(),
    ssh_ca_id: z.uuid().optional(),
    status: z.enum(['active', 'revoked', 'expired']).optional(),
    query: z.string().max(100).optional(),
    ...paginationSchema,
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const { rows, next_cursor, counts } = await listSshCertificates(useContext(), actor, body)
    return { data: rows.map((row) => presentSshCertificate(actor, row)), next_cursor, counts }
  },
)
