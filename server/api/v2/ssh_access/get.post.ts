import { z } from 'zod'
import { resolveSshAccess } from '@certifly/core/ssh-access'
import { presentSshAccess } from '@certifly/core/ssh-presenters'

/**
 * What the signed-in person may do over SSH
 *
 * Their SSH username and the host groups where they hold at least one login, each with the
 * logins (their own username already filled in), principals (`<slug>:<login>`), key policy,
 * lifetimes, extensions, host patterns and the CA public key. Works with a command-line session,
 * an API key or a browser session.
 */
export default defineRpc(z.object({}), async (event) => {
  const { user } = await requireAuth(event)
  const { username, access } = await resolveSshAccess(useContext().db, user)
  return presentSshAccess(user, username, access)
})
