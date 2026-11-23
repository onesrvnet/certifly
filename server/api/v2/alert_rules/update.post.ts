import { z } from 'zod'
import { updateAlertRule } from '@certifly/core/alerts'
import { presentAlertRule } from '@certifly/core/presenters'

/**
 * Update an alert rule
 *
 * Changes any of the rule's settings (see `alert_rules.create`); what is left out stays. Set
 * `enabled: false` to pause it. Admins only, from a recently re-authenticated session.
 */
export default defineRpc(
  z.object({
    id: z.uuid(),
    name: z.string().max(100).optional(),
    event: z.enum(['expiring', 'issued', 'revoked', 'ca_expiring', 'crl_failed', 'ssh_host_expiring']).optional(),
    ca_ids: z.array(z.uuid()).max(100).optional(),
    template_ids: z.array(z.uuid()).max(100).optional(),
    include_imported: z.boolean().optional(),
    days_before: z.array(z.number().int()).max(10).optional(),
    channel_ids: z.array(z.uuid()).min(1).max(10).optional(),
    enabled: z.boolean().optional(),
  }),
  async (event, { id, ...body }) => {
    const { actor } = await requireAuth(event)
    return { data: presentAlertRule(actor, await updateAlertRule(useContext(), actor, id, body)) }
  },
)
