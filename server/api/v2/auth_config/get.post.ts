import { z } from 'zod'
import { setupMethod } from '@certifly/core/auth/setup'

/**
 * Get the sign-in configuration
 *
 * Public. Tells the sign-in pages how the instance gets its first admin (`setup_method`, null
 * once it has one), whether setting it up needs the setup token, whether signing in by email
 * is possible (`email_enabled`: false when the instance cannot send mail) and whether sign-in
 * with the configured OpenID Connect provider is offered.
 *
 * `setup_method` is `email` (the first email sign-in becomes admin), `token` (no mail: the
 * setup token creates the admin with `setup_accounts.create`, also to get back in before that
 * admin has added a passkey), `oidc_only` (no mail and no setup token: the first sign-in with
 * the provider becomes admin) or `unavailable` (none of these is configured).
 */
export default defineRpc(z.object({}), async () => {
  const ctx = useContext()
  const method = await setupMethod(ctx, { oidc_enabled: oidcEnabled() })
  const needsSetup = method !== null
  return {
    data: {
      needs_setup: needsSetup,
      setup_method: method,
      setup_token_required: needsSetup && !!ctx.setup_token?.trim(),
      email_enabled: ctx.mailer.delivers,
      oidc: { enabled: oidcEnabled(), display_name: env().OIDC_DISPLAY_NAME },
    },
  }
})
