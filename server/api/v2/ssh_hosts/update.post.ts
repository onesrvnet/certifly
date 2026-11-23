import { z } from 'zod'
import { getSshHost, updateSshHost } from '@certifly/core/ssh-hosts'
import { presentSshHost } from '@certifly/core/ssh-presenters'

/**
 * Update an SSH host
 *
 * Changes the name, host names, public keys or host group. Changing names, keys or host group
 * revokes the host's valid certificates; it gets new ones when it next syncs. Operators and
 * admins, also with API keys.
 */
export default defineRpc(
  z.object({
    id: z.uuid(),
    name: z.string().max(253).optional(),
    host_group_id: z.uuid().optional(),
    hostnames: z.array(z.string().max(253)).min(1).max(20).optional(),
    public_keys: z.array(sshPublicKeyLine).min(1).max(10).optional(),
  }),
  async (event, { id, ...body }) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    await updateSshHost(ctx, actor, id, body)
    return { data: presentSshHost(actor, await getSshHost(ctx, actor, id)) }
  },
)
