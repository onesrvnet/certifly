import { z } from 'zod'
import { createSshHost, getSshHost } from '@certifly/core/ssh-hosts'
import { presentSshHost } from '@certifly/core/ssh-presenters'

/**
 * Add an SSH host
 *
 * Registers a host by hand: `hostnames` must match the host group's patterns
 * (`host_name_not_allowed`), `public_keys` are its host keys as authorized_keys lines
 * (`ssh_key_type`). `name` defaults to the first host name (`host_name_taken`). Its certificates
 * are issued when it first syncs. Operators and admins, also with API keys.
 */
export default defineRpc(
  z.object({
    host_group_id: z.uuid(),
    name: z.string().max(253).optional(),
    hostnames: z.array(z.string().max(253)).min(1).max(20),
    public_keys: z.array(sshPublicKeyLine).min(1).max(10),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const host = await createSshHost(ctx, actor, body)
    return { data: presentSshHost(actor, await getSshHost(ctx, actor, host.id)) }
  },
)
