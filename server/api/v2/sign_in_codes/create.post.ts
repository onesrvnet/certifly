import { z } from 'zod'
import { requestEmailSignin } from '@certifly/core/auth/email'

/**
 * Request a sign-in code
 *
 * Emails a one-time code and link. The answer is the same whether or not the address may
 * sign in. On an empty instance the first sign-in becomes admin and needs `setup_token`
 * when the server has one configured.
 */
export default defineRpc(z.object({ email: z.string().max(320), setup_token: z.string().max(500).optional() }), async (event, body) => {
  await limit(event, 'signinRequest', clientIp(event))
  await requestEmailSignin(useContext(), body)
  return { data: { sent: true } }
})
