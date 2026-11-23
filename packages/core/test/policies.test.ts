import { describe, expect, it } from 'vitest'
import { AuthorizationError } from '../src/errors'
import { type Actor, apiKeyPolicy, auditPolicy, authorize, hasRole, invitePolicy, peoplePolicy, settingsPolicy, userPolicy } from '../src/policies'

const actor = (role: Actor['role'], kind: Actor['kind'] = 'session', id = `${role}-1`): Actor => ({ id, role, kind, reauth_at: null })
const admin = actor('admin')
const operator = actor('operator')
const viewer = actor('viewer')

describe('roles', () => {
  it('ranks admin above operator above viewer', () => {
    expect(hasRole(admin, 'operator')).toBe(true)
    expect(hasRole(operator, 'admin')).toBe(false)
    expect(hasRole(viewer, 'viewer')).toBe(true)
    expect(hasRole(viewer, 'operator')).toBe(false)
  })
})

describe('users', () => {
  const someone = { id: 'someone-else', role: 'viewer' as const }

  it('lets admins read, update, change roles of and deactivate anyone', () => {
    expect(userPolicy.abilities(admin, someone)).toEqual({ read: true, update: true, change_role: true, deactivate: true, reactivate: true, set_username: true })
  })

  it('lets everyone else read and update only themselves, and never change roles', () => {
    for (const person of [operator, viewer]) {
      expect(userPolicy.abilities(person, { id: person.id, role: person.role })).toEqual({
        read: true,
        update: true,
        change_role: false,
        deactivate: false,
        reactivate: false,
        set_username: false,
      })
      expect(userPolicy.can(person, 'read', someone)).toBe(false)
      expect(userPolicy.can(person, 'update', someone)).toBe(false)
    }
  })
})

describe('people', () => {
  it('may be listed in full by admins only', () => {
    expect(peoplePolicy.can(admin, 'list', undefined)).toBe(true)
    expect(peoplePolicy.can(operator, 'list', undefined)).toBe(false)
    expect(peoplePolicy.can(viewer, 'list', undefined)).toBe(false)
  })
})

describe('invites and settings', () => {
  it('are for admins only', () => {
    for (const action of ['read', 'create', 'revoke'] as const) {
      expect(invitePolicy.can(admin, action, undefined)).toBe(true)
      expect(invitePolicy.can(operator, action, undefined)).toBe(false)
      expect(invitePolicy.can(viewer, action, undefined)).toBe(false)
    }
    for (const action of ['read', 'update'] as const) {
      expect(settingsPolicy.can(admin, action, undefined)).toBe(true)
      expect(settingsPolicy.can(operator, action, undefined)).toBe(false)
    }
  })
})

describe('api keys', () => {
  it('belong to their owner, whatever the role', () => {
    for (const person of [admin, operator, viewer]) {
      expect(apiKeyPolicy.can(person, 'read', { user_id: person.id })).toBe(true)
      expect(apiKeyPolicy.can(person, 'delete', { user_id: person.id })).toBe(true)
      expect(apiKeyPolicy.can(person, 'read', { user_id: 'another' })).toBe(false)
      expect(apiKeyPolicy.can(person, 'delete', { user_id: 'another' })).toBe(false)
    }
  })

  it('cannot be created by an API key, so a leaked key cannot spread', () => {
    const viaKey = actor('admin', 'api_key', admin.id)
    expect(apiKeyPolicy.can(admin, 'create', { user_id: admin.id })).toBe(true)
    expect(apiKeyPolicy.can(viaKey, 'create', { user_id: admin.id })).toBe(false)
    expect(apiKeyPolicy.can(viaKey, 'read', { user_id: admin.id })).toBe(true)
  })

  it('cannot be created for someone else', () => {
    expect(apiKeyPolicy.can(admin, 'create', { user_id: 'another' })).toBe(false)
  })
})

describe('audit log', () => {
  it('can be read by every role', () => {
    for (const person of [admin, operator, viewer]) expect(auditPolicy.can(person, 'read', undefined)).toBe(true)
  })

  it('has no other action, so nobody may change it', () => {
    expect(Object.keys(auditPolicy.abilities(admin, undefined))).toEqual(['read'])
  })
})

describe('authorize', () => {
  it('throws a 403 when the policy refuses', () => {
    expect(() => authorize(invitePolicy, viewer, 'create', undefined)).toThrow(AuthorizationError)
    expect(() => authorize(invitePolicy, admin, 'create', undefined)).not.toThrow()
  })
})
