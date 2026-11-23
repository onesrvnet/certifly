import { z } from 'zod'
import { listSshAccessRules, updateSshAccessRule } from '@certifly/core/ssh-access'
import { presentSshAccessRule } from '@certifly/core/ssh-presenters'

/** Update an SSH access rule: its fixed `logins` and `own_username`. Admins, also with API keys. */
export default defineRpc(
  z.object({ id: z.uuid(), logins: z.array(z.string().max(40)).max(50).optional(), own_username: z.boolean().optional() }),
  async (event, { id, ...body }) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const rule = await updateSshAccessRule(ctx, actor, id, body)
    const { rows } = await listSshAccessRules(ctx, actor, { host_group_id: rule.host_group_id, group_id: rule.group_id, limit: 1 })
    return { data: presentSshAccessRule(actor, rows.find((r) => r.id === id)!) }
  },
)
