import { z } from 'zod'
import { startSecurityKeyEnrollment, SECURITY_KEY_POLL_INTERVAL_SECONDS } from '@certifly/core/ssh-security-keys'

/**
 * Start registering a security key
 *
 * Only for a command-line session. Answers with the `enrollment_id`, a base64 `challenge` of 32
 * bytes for `ssh-keygen -O challenge=`, the `user_code` shown on both screens, the `browser_url`
 * where the person approves the key, the polling `interval_seconds` and `expires_at` (10 minutes).
 */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  await limit(event, 'securityKeyEnrollment', `cli:${actor.cli_session_id ?? actor.id}`)
  const { enrollment, browser_url } = await startSecurityKeyEnrollment(useContext(), actor)
  return {
    enrollment_id: enrollment.id,
    challenge: Buffer.from(enrollment.challenge).toString('base64'),
    user_code: enrollment.user_code,
    browser_url,
    interval_seconds: SECURITY_KEY_POLL_INTERVAL_SECONDS,
    expires_at: enrollment.expires_at.toISOString(),
  }
})
