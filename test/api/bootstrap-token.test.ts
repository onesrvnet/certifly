import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { Client, latestSigninMail, resetState, sentMails, serverOptions } from '../helpers'

describe('bootstrap with a setup token', async () => {
  await setup({ ...serverOptions, env: { SETUP_TOKEN: 'correct-horse-battery' } })
  beforeEach(resetState)

  it('tells the sign-in page that the token is needed', async () => {
    const { body } = await new Client().rpc('auth_config.get')
    expect(body.data).toMatchObject({ needs_setup: true, setup_token_required: true })
  })

  it('refuses the first sign-in without the token', async () => {
    const { status, body } = await new Client().rpc('sign_in_codes.create', { email: 'admin@example.com' })
    expect(status).toBe(403)
    expect(body.error.code).toBe('setup_token_required')
    expect(await sentMails('admin@example.com')).toHaveLength(0)
  })

  it('refuses a wrong token, also one that only differs in case', async () => {
    for (const setup_token of ['wrong', 'Correct-Horse-Battery']) {
      const { status, body } = await new Client().rpc('sign_in_codes.create', { email: 'admin@example.com', setup_token })
      expect(status).toBe(403)
      expect(body.error.code).toBe('setup_token_invalid')
    }
    expect(await sentMails('admin@example.com')).toHaveLength(0)
  })

  it('accepts the token once and then makes the person admin, without asking again at the code step', async () => {
    const client = new Client()
    expect((await client.rpc('sign_in_codes.create', { email: 'admin@example.com', setup_token: 'correct-horse-battery' })).status).toBe(200)
    const { code } = await latestSigninMail('admin@example.com')
    expect((await client.rpc('sign_in_codes.verify', { email: 'admin@example.com', code })).status).toBe(200)
    expect((await client.rpc('sessions.get')).body.data.user.role).toBe('admin')
    expect((await new Client().rpc('auth_config.get')).body.data).toMatchObject({ needs_setup: false, setup_token_required: false })
  })

  it('ignores the token after setup: strangers still need an invite', async () => {
    const admin = new Client()
    await admin.rpc('sign_in_codes.create', { email: 'admin@example.com', setup_token: 'correct-horse-battery' })
    await admin.rpc('sign_in_codes.verify', { token: (await latestSigninMail('admin@example.com')).token })

    const stranger = await new Client().rpc('sign_in_codes.create', { email: 'stranger@example.com', setup_token: 'correct-horse-battery' })
    expect(stranger.status).toBe(200)
    expect(await sentMails('stranger@example.com')).toHaveLength(0)
  })
})
