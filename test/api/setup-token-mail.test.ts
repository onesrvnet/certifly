import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, resetState, serverOptions } from '../helpers'

const SETUP_TOKEN = 'setup-token-for-tests-0123456789'

describe('setup by token is off when the instance can send mail', async () => {
  await setup({ ...serverOptions, env: { SETUP_TOKEN } })
  beforeEach(resetState)

  it('answers token_setup_unavailable and leaves setup to email', async () => {
    expect((await new Client().rpc('auth_config.get')).body.data.setup_method).toBe('email')
    const refused = await new Client().rpc('setup_accounts.create', { setup_token: SETUP_TOKEN, email: 'admin@example.com' })
    expect(refused.status).toBe(403)
    expect(refused.body.error.code).toBe('token_setup_unavailable')
  })
})
