import { describe, expect, it } from 'vitest'
import { decideNewUser, refusal } from '../src/auth/provision'

const base = { method: 'email' as const }

describe('first sign-in on an empty instance', () => {
  it('becomes admin when no setup token is configured', () => {
    expect(decideNewUser({ ...base, user_count: 0 })).toEqual({ allow: true, role: 'admin', via: 'bootstrap' })
  })

  it('treats a blank setup token as not configured', () => {
    expect(decideNewUser({ ...base, user_count: 0, setup_token: '  ' })).toMatchObject({ allow: true, role: 'admin' })
  })

  it('becomes admin with the matching setup token', () => {
    expect(decideNewUser({ ...base, user_count: 0, setup_token: 's3cret', presented_token: 's3cret' })).toEqual({
      allow: true,
      role: 'admin',
      via: 'bootstrap',
    })
  })

  it('ignores whitespace around the presented token', () => {
    expect(decideNewUser({ ...base, user_count: 0, setup_token: 's3cret', presented_token: ' s3cret\n' })).toMatchObject({ allow: true })
  })

  it('needs the token when one is configured', () => {
    expect(decideNewUser({ ...base, user_count: 0, setup_token: 's3cret' })).toEqual({ allow: false, reason: 'setup_token_required' })
    expect(decideNewUser({ ...base, user_count: 0, setup_token: 's3cret', presented_token: '' })).toEqual({
      allow: false,
      reason: 'setup_token_required',
    })
  })

  it('refuses a wrong token, including one that is a prefix or an extension of the right one', () => {
    for (const presented_token of ['wrong', 's3cre', 's3cret!', 'S3CRET']) {
      expect(decideNewUser({ ...base, user_count: 0, setup_token: 's3cret', presented_token })).toEqual({
        allow: false,
        reason: 'setup_token_invalid',
      })
    }
  })

  it('accepts a token that was already checked when the code was requested', () => {
    expect(decideNewUser({ ...base, user_count: 0, setup_token: 's3cret', setup_proven: true })).toMatchObject({ allow: true, role: 'admin' })
  })

  it('applies to OpenID Connect too', () => {
    expect(decideNewUser({ method: 'oidc', user_count: 0, setup_token: 's3cret' })).toMatchObject({ allow: false })
    expect(decideNewUser({ method: 'oidc', user_count: 0 })).toMatchObject({ allow: true, role: 'admin' })
  })
})

describe('after the first user', () => {
  it('refuses people nobody invited when they sign in by email', () => {
    expect(decideNewUser({ ...base, user_count: 1 })).toEqual({ allow: false, reason: 'invite_required' })
  })

  it('does not let the setup token create accounts', () => {
    expect(decideNewUser({ ...base, user_count: 3, setup_token: 's3cret', presented_token: 's3cret' })).toEqual({
      allow: false,
      reason: 'invite_required',
    })
    expect(decideNewUser({ ...base, user_count: 3, setup_token: 's3cret', setup_proven: true })).toMatchObject({ allow: false })
  })

  it('admits people with a pending invite, with the invited role', () => {
    for (const role of ['admin', 'operator', 'viewer'] as const) {
      expect(decideNewUser({ ...base, user_count: 1, invite: { role } })).toEqual({ allow: true, role, via: 'invite' })
    }
  })

  it('admits OpenID Connect users as viewers by default', () => {
    expect(decideNewUser({ method: 'oidc', user_count: 1 })).toEqual({ allow: true, role: 'viewer', via: 'oidc' })
  })

  it('lets the mapping hook choose the role of OpenID Connect users', () => {
    expect(decideNewUser({ method: 'oidc', user_count: 1, oidc_role: 'admin' })).toEqual({ allow: true, role: 'admin', via: 'oidc' })
    expect(decideNewUser({ method: 'oidc', user_count: 1, oidc_role: null })).toMatchObject({ role: 'viewer' })
  })

  it('prefers the invited role over the mapping hook', () => {
    expect(decideNewUser({ method: 'oidc', user_count: 1, invite: { role: 'operator' }, oidc_role: 'admin' })).toMatchObject({
      role: 'operator',
      via: 'invite',
    })
  })

  it('never lets the mapping hook affect email sign-in', () => {
    expect(decideNewUser({ ...base, user_count: 1, oidc_role: 'admin' })).toMatchObject({ allow: false })
  })
})

describe('refusal', () => {
  it('maps each reason to a stable error code', () => {
    expect(refusal('setup_token_required')).toMatchObject({ status: 403, code: 'setup_token_required' })
    expect(refusal('setup_token_invalid')).toMatchObject({ status: 403, code: 'setup_token_invalid' })
    expect(refusal('invite_required')).toMatchObject({ status: 403, code: 'invite_required' })
  })
})
