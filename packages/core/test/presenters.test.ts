import { describe, expect, it } from 'vitest'
import type { ApiKeyRow } from '../src/api-keys'
import type { EventRow } from '../src/audit'
import { inviteStatus, type InviteRow } from '../src/invites'
import type { Actor } from '../src/policies'
import { presentApiKey, presentEvent, presentInvite, presentUser } from '../src/presenters'
import type { UserRow } from '../src/users'

const date = new Date('2026-11-22T12:00:00Z')
const admin: Actor = { id: 'u1', role: 'admin', kind: 'session', reauth_at: null }
const viewer: Actor = { id: 'u2', role: 'viewer', kind: 'session', reauth_at: null }

const user = {
  id: 'u2', email: 'bob@example.com', name: 'Bob', role: 'viewer', preferences: {}, last_active_at: null,
  last_signed_in_at: date, created_at: date, updated_at: date, deleted_at: null,
} as UserRow

describe('presentUser', () => {
  it('formats dates and attaches what the viewer may do', () => {
    const shown = presentUser(admin, user)
    expect(shown).toMatchObject({ email: 'bob@example.com', last_active_at: null, last_signed_in_at: '2026-11-22T12:00:00.000Z' })
    expect(shown.permissions).toMatchObject({ change_role: true, deactivate: true })
    expect(Object.keys(shown)).not.toContain('updated_at')
  })

  it('shows a user their own limits', () => {
    expect(presentUser(viewer, user).permissions).toMatchObject({ update: true, change_role: false, deactivate: false })
  })
})

describe('presentApiKey', () => {
  const key = { id: 'k1', user_id: 'u2', name: 'ci', secret_hash: 'h', last4: 'abcd', expires_at: null, last_used_at: null, created_at: date, updated_at: date } as ApiKeyRow

  it('never includes the secret hash', () => {
    const shown = presentApiKey(viewer, key)
    expect(shown).not.toHaveProperty('secret_hash')
    expect(shown).toMatchObject({ last4: 'abcd', permissions: { read: true, create: true, delete: true } })
  })

  it('does not offer a key to someone else', () => {
    expect(presentApiKey(admin, key).permissions).toEqual({ read: false, create: false, delete: false })
  })
})

describe('invites', () => {
  const invite = (fields: Partial<InviteRow>) =>
    ({ id: 'i1', email: 'c@example.com', role: 'viewer', invited_by_id: 'u1', token_hash: 'h', expires_at: new Date('2026-12-01T00:00:00Z'), accepted_at: null, created_at: date, updated_at: date, ...fields }) as InviteRow
  const now = new Date('2026-11-22T12:00:00Z')

  it('is pending until it is accepted or expires', () => {
    expect(inviteStatus(invite({}), now)).toBe('pending')
    expect(inviteStatus(invite({ accepted_at: date }), now)).toBe('accepted')
    expect(inviteStatus(invite({ expires_at: new Date('2026-11-22T12:00:00Z') }), now)).toBe('expired')
    expect(inviteStatus(invite({ accepted_at: date, expires_at: new Date('2020-01-01') }), now)).toBe('accepted')
  })

  it('never includes the token hash', () => {
    expect(presentInvite(admin, invite({}))).not.toHaveProperty('token_hash')
    expect(presentInvite(viewer, invite({})).permissions).toEqual({ read: false, create: false, revoke: false })
  })
})

describe('presentEvent', () => {
  it('adds the acting user name to the row', () => {
    const event = { id: 'e1', actor_type: 'user', actor_id: 'u1', name: 'users.create', subject_type: 'user', subject_id: 'u2', data: {}, ip: null, created_at: date } as EventRow
    expect(presentEvent(viewer, { event, actor_name: 'Ann' })).toMatchObject({
      actor_name: 'Ann',
      created_at: '2026-11-22T12:00:00.000Z',
      permissions: { read: true },
    })
  })
})
