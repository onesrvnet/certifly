import { z } from 'zod'
import { startCliLogin } from '@certifly/core/cli-auth'

/**
 * Start a command-line sign-in
 *
 * No sign-in. `code_challenge` is the base64url SHA-256 of the `code_verifier` the CLI keeps.
 * Answers with `login_id`, `device_code`, a short `user_code` shown on both screens, the
 * `browser_url` to open, the polling `interval_seconds` and `expires_at` (10 minutes). The person
 * approves in the browser; the CLI polls `cli_logins.poll`.
 */
export default defineRpc(
  z.object({ code_challenge: z.string().max(100), machine: z.object({ hostname: z.string().max(200), os: z.string().max(100) }) }),
  async (event, body) => {
    await limit(event, 'cliLogin', clientIp(event))
    const login = await startCliLogin(useContext(), { ...body, ip: requestIp(event) })
    return { ...login, expires_at: login.expires_at.toISOString() }
  },
)
