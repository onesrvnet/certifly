import { z } from 'zod'
import { getGroup, updateGroup } from '@certifly/core/groups'
import { presentGroup } from '@certifly/core/ssh-presenters'

/** Update a group's name, description or provider group names. Admins, also with API keys. */
export default defineRpc(
  z.object({ id: z.uuid(), name: z.string().max(200).optional(), description: z.string().max(1000).optional(), provider_groups: z.array(z.string().max(200)).max(50).optional() }),
  async (event, { id, ...body }) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    await updateGroup(ctx, actor, id, body)
    return { data: presentGroup(actor, await getGroup(ctx, actor, id)) }
  },
)
