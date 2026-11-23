import { z } from 'zod'
import { bootstrapAdmin } from '@certifly/core/auth/setup'

/**
 * Create the first admin with the setup token
 *
 * Public, for an instance that cannot send mail and has a `SETUP_TOKEN`: creates the admin
 * account from `email` and `name` and starts a session; the page then asks for a passkey.
 * Until that admin has a passkey (or a linked identity), calling this again with the same token
 * and email signs back into the same account, so leaving early locks nobody out. A different
 * email is refused (`setup_email_mismatch`). A wrong token and an instance that is already set up both
 * get `setup_token_invalid`; an instance that can send mail, or has no setup token, gets
 * `token_setup_unavailable`.
 */
export default defineRpc(
  z.object({ setup_token: z.string().min(1).max(500), email: z.string().max(320), name: z.string().max(100).optional() }),
  async (event, body) => {
    await limit(event, 'signinRequest', clientIp(event))
    const user = await bootstrapAdmin(useContext(), body)
    await signIn(event, user, 'setup_token')
    return { data: { signed_in: true } }
  },
)
