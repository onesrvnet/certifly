import { z } from 'zod'
import { createAlertRule } from '@certifly/core/alerts'
import { presentAlertRule } from '@certifly/core/presenters'

/**
 * Create an alert rule
 *
 * `event` is one of `expiring`, `ca_expiring` and `ssh_host_expiring` (all need `days_before`, e.g.
 * `[30, 7, 1]`; each threshold is sent once per certificate, CA or SSH host certificate, which
 * take no filters), `issued`, `revoked` or `crl_failed`.
 * Filters: `ca_ids` and `template_ids` (empty for all) and `include_imported` (inventory
 * certificates, expiry warnings only). Alerts go to every channel in `channel_ids`. Admins only,
 * from a recently re-authenticated session.
 */
export default defineRpc(
  z.object({
    name: z.string().max(100),
    event: z.enum(['expiring', 'issued', 'revoked', 'ca_expiring', 'crl_failed', 'ssh_host_expiring']),
    ca_ids: z.array(z.uuid()).max(100).optional(),
    template_ids: z.array(z.uuid()).max(100).optional(),
    include_imported: z.boolean().optional(),
    days_before: z.array(z.number().int()).max(10).optional(),
    channel_ids: z.array(z.uuid()).min(1).max(10),
    enabled: z.boolean().optional(),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    return { data: presentAlertRule(actor, await createAlertRule(useContext(), actor, body)) }
  },
)
