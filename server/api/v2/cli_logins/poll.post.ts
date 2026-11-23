import { z } from 'zod'
import { pollCliLogin } from '@certifly/core/cli-auth'

/**
 * Poll a command-line sign-in
 *
 * No sign-in; `device_code` and the `code_verifier` that belongs to the start's challenge prove
 * it is the CLI that started it (`invalid_code_verifier`). Answers `{status: "pending"}`, or
 * `{status: "approved", token, expires_at, user}` once, with the `cfc_` token. Errors:
 * `cli_login_denied` (403), `cli_login_expired` (410), `slow_down` (429: poll less often).
 */
export default defineRpc(z.object({ device_code: z.string().max(200), code_verifier: z.string().max(200) }), async (event, body) => {
  await limit(event, 'cliLogin', clientIp(event))
  const result = await pollCliLogin(useContext(), body)
  return result.status === 'pending' ? result : { ...result, expires_at: result.expires_at.toISOString() }
})
