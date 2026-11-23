import { z } from 'zod'
import { createGroup, getGroup } from '@certifly/core/groups'
import { presentGroup } from '@certifly/core/ssh-presenters'

/**
 * Create a group
 *
 * A group of people for SSH access rules. The `name` is unique whatever its case
 * (`group_name_taken`). `provider_groups` lists group names at the identity provider
 * (`OIDC_GROUPS_CLAIM`): people who sign in with a matching provider group become members.
 * Admins, also with API keys.
 */
export default defineRpc(
  z.object({ name: z.string().max(200), description: z.string().max(1000).optional(), provider_groups: z.array(z.string().max(200)).max(50).optional() }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const group = await createGroup(ctx, actor, body)
    return { data: presentGroup(actor, await getGroup(ctx, actor, group.id)) }
  },
)
