import { z } from 'zod'
import { deactivateUser, reactivateUser, updateUser, updateUserRole } from '@certifly/core/users'
import { presentUser } from '@certifly/core/presenters'

/**
 * Update a person
 *
 * People update their own name and preferences; admins can update anyone. Only admins change
 * `role`, `deactivated` or `username` (the SSH username: lowercase letters, digits, `_`, `.` and `-`,
 * unique whatever the case, never a system account name such as root). The last admin cannot be demoted or deactivated (`last_admin`).
 * Deactivating signs a person out everywhere, deletes their API keys and the invites they sent,
 * and blocks sign-in until they are reactivated. Changing a role and (de)activating need a
 * recently re-authenticated session (`reauth_required`).
 */
export default defineRpc(
  z.object({
    id: z.uuid().optional(),
    name: z.string().max(100).optional(),
    username: z.string().max(40).optional(),
    preferences: z.record(z.string(), z.unknown()).optional(),
    role: z.enum(['admin', 'operator', 'viewer']).optional(),
    deactivated: z.boolean().optional(),
  }),
  async (event, { id, role, deactivated, ...input }) => {
    const { actor } = await requireAuth(event)
    const ctx = useContext()
    const target = id ?? actor.id
    let updated = role ? await updateUserRole(ctx, actor, target, role) : undefined
    if (deactivated !== undefined) updated = deactivated ? await deactivateUser(ctx, actor, target) : await reactivateUser(ctx, actor, target)
    if (Object.values(input).some((value) => value !== undefined) || !updated) updated = await updateUser(ctx, actor, target, input)
    return { data: presentUser(actor, updated) }
  },
)
