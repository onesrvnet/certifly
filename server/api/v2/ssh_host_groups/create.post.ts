import { z } from 'zod'
import { createSshHostGroup, getSshHostGroup } from '@certifly/core/ssh-host-groups'
import { presentSshHostGroup } from '@certifly/core/ssh-presenters'

/**
 * Create an SSH host group
 *
 * A set of hosts with shared rules, signed by one SSH CA. The `slug` is the first part of every
 * principal (`prod:root`) and cannot change (`slug_taken`). Defaults: user certificates last 8
 * hours (at most 24 hours; never more than 7 days), extension `permit-pty`, key policy `any`
 * (`sk` needs a security key, `sk_attested` also a genuine Yubico attestation), host
 * certificates last 90 days (at most 365). `host_patterns` are domain patterns such as
 * `*.prod.corp`; a host can only join with names that match one. Admins, also with API keys.
 */
export default defineRpc(
  z.object({ name: z.string().max(200), slug: z.string().max(100), ssh_ca_id: z.uuid(), ...sshHostGroupSettings }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const group = await createSshHostGroup(ctx, actor, body)
    return { data: presentSshHostGroup(actor, await getSshHostGroup(ctx, actor, group.id)) }
  },
)
