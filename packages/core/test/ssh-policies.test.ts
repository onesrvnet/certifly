import { describe, expect, it } from 'vitest'
import { type Actor, sshAccessPolicy, sshCaPolicy, sshCertificatePolicy, sshHostGroupPolicy, sshHostPolicy, sshJoinTokenPolicy } from '../src/policies'

const actor = (role: Actor['role'], kind: Actor['kind'] = 'session'): Actor => ({ id: `${role}-1`, role, kind, reauth_at: null })

describe('SSH policies', () => {
  it('lets everyone read CAs, and only admin sessions change them', () => {
    for (const role of ['viewer', 'operator', 'admin'] as const) expect(sshCaPolicy.can(actor(role), 'read', undefined)).toBe(true)
    expect(sshCaPolicy.can(actor('admin'), 'create', undefined)).toBe(true)
    for (const other of [actor('operator'), actor('admin', 'api_key'), actor('admin', 'cli')]) {
      for (const action of ['create', 'import', 'update', 'delete'] as const) expect(sshCaPolicy.can(other, action, undefined)).toBe(false)
    }
  })

  it('lets operators read host groups and only admin sessions change them', () => {
    expect(sshHostGroupPolicy.abilities(actor('viewer'), undefined)).toEqual({ read: false, manage: false })
    expect(sshHostGroupPolicy.abilities(actor('operator'), undefined)).toEqual({ read: true, manage: false })
    expect(sshHostGroupPolicy.abilities(actor('admin'), undefined)).toEqual({ read: true, manage: true })
    expect(sshHostGroupPolicy.abilities(actor('admin', 'api_key'), undefined)).toEqual({ read: true, manage: false })
    expect(sshHostGroupPolicy.can(actor('admin', 'cli'), 'manage', undefined)).toBe(false)
  })

  it('keeps groups and rules to admins, changes to admin sessions, and tokens to admin sessions', () => {
    expect(sshAccessPolicy.can(actor('operator'), 'read', undefined)).toBe(false)
    expect(sshAccessPolicy.can(actor('admin', 'api_key'), 'read', undefined)).toBe(true)
    expect(sshAccessPolicy.can(actor('admin'), 'manage', undefined)).toBe(true)
    expect(sshAccessPolicy.can(actor('admin', 'api_key'), 'manage', undefined)).toBe(false)
    expect(sshJoinTokenPolicy.can(actor('admin', 'api_key'), 'create', undefined)).toBe(false)
    expect(sshJoinTokenPolicy.can(actor('admin'), 'create', undefined)).toBe(true)
  })

  it('lets operators manage hosts', () => {
    expect(sshHostPolicy.can(actor('viewer'), 'read', undefined)).toBe(false)
    expect(sshHostPolicy.can(actor('operator', 'api_key'), 'manage', undefined)).toBe(true)
  })

  it('shows and revokes own user certificates to anyone, all certificates to operators; only admin sessions sign for others', () => {
    const own = { kind: 'user' as const, user_id: 'viewer-1' }
    expect(sshCertificatePolicy.abilities(actor('viewer'), own)).toEqual({ read: true, revoke: true, sign_for_others: false })
    expect(sshCertificatePolicy.can(actor('viewer'), 'read', { kind: 'user', user_id: 'someone' })).toBe(false)
    expect(sshCertificatePolicy.can(actor('viewer'), 'read', { kind: 'host', user_id: null })).toBe(false)
    expect(sshCertificatePolicy.can(actor('operator'), 'revoke', { kind: 'host', user_id: null })).toBe(true)
    expect(sshCertificatePolicy.can(actor('operator'), 'sign_for_others', undefined)).toBe(false)
    expect(sshCertificatePolicy.can(actor('admin', 'api_key'), 'sign_for_others', undefined)).toBe(false)
    expect(sshCertificatePolicy.can(actor('admin'), 'sign_for_others', undefined)).toBe(true)
  })
})
