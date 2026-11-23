import { z } from 'zod'
import { getSshHostGroup, updateSshHostGroup } from '@certifly/core/ssh-host-groups'
import { presentSshHostGroup } from '@certifly/core/ssh-presenters'

/**
 * Update an SSH host group
 *
 * Changes what is given. The slug and the SSH CA never change. New settings apply to
 * certificates signed afterwards; certificates already issued keep what they were signed with.
 * Admins, also with API keys.
 */
export default defineRpc(z.object({ id: z.uuid(), name: z.string().max(200).optional(), ...sshHostGroupSettings }), async (event, { id, ...body }) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await updateSshHostGroup(ctx, actor, id, body)
  return { data: presentSshHostGroup(actor, await getSshHostGroup(ctx, actor, id)) }
})
