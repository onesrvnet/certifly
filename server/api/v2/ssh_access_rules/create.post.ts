import { z } from 'zod'
import { createSshAccessRule, listSshAccessRules } from '@certifly/core/ssh-access'
import { presentSshAccessRule } from '@certifly/core/ssh-presenters'

/**
 * Create an SSH access rule
 *
 * Lets the members of `group_id` log in to `host_group_id` as the fixed local `logins` and, with
 * `own_username`, as their own username. A rule needs at least one of them (`rule_empty`); a
 * group has one rule per host group (`rule_exists`). Takes effect with the next certificate a
 * member signs. Admins, also with API keys.
 */
export default defineRpc(
  z.object({ host_group_id: z.uuid(), group_id: z.uuid(), logins: z.array(z.string().max(40)).max(50).optional(), own_username: z.boolean().optional() }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const rule = await createSshAccessRule(ctx, actor, body)
    const { rows } = await listSshAccessRules(ctx, actor, { host_group_id: body.host_group_id, group_id: body.group_id, limit: 1 })
    return { data: presentSshAccessRule(actor, rows.find((r) => r.id === rule.id)!) }
  },
)
