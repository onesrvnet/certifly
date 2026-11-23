import { z } from 'zod'
import { createInvite } from '@certifly/core/invites'
import { presentInvite } from '@certifly/core/presenters'

/**
 * Invite someone
 *
 * Admins invite an email address with a role and the address gets a link to /invite. An
 * earlier pending invite for the same address is replaced; an address that already has an
 * account is refused (`user_exists`). When the instance cannot send mail, `link` holds the
 * invite link to pass on; it is in this response only. Otherwise `link` is null. Needs a
 * recently re-authenticated session (`reauth_required`).
 */
export default defineRpc(z.object({ email: z.string().max(320), role: z.enum(['admin', 'operator', 'viewer']).default('viewer') }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { invite, link, mailed } = await createInvite(useContext(), actor, body)
  return { data: { ...presentInvite(actor, invite), link: mailed ? null : link } }
})
