import { describe, expect, it } from 'vitest'
import { assertFreshAuthTime, assertRecentReauth, assertStepUp, STEP_UP_MAX_AGE_MS } from '../src/auth/sessions'
import { AuthenticationError, AuthorizationError } from '../src/errors'
import type { Actor } from '../src/policies'

const now = new Date('2026-11-22T12:00:00Z')
const ago = (ms: number) => new Date(now.getTime() - ms)
const TEN_MINUTES = 10 * 60 * 1000

describe('assertRecentReauth', () => {
  it('passes for a session re-authenticated within the limit', () => {
    expect(() => assertRecentReauth({ reauth_at: ago(0) }, TEN_MINUTES, now)).not.toThrow()
    expect(() => assertRecentReauth({ reauth_at: ago(TEN_MINUTES - 1) }, TEN_MINUTES, now)).not.toThrow()
    expect(() => assertRecentReauth({ reauth_at: ago(TEN_MINUTES) }, TEN_MINUTES, now)).not.toThrow()
  })

  it('refuses one that is older', () => {
    expect(() => assertRecentReauth({ reauth_at: ago(TEN_MINUTES + 1) }, TEN_MINUTES, now)).toThrow(AuthorizationError)
  })

  it('refuses a session that never re-authenticated', () => {
    expect(() => assertRecentReauth({ reauth_at: null }, TEN_MINUTES, now)).toThrow(AuthorizationError)
  })

  it('always refuses API keys, which have no session', () => {
    expect(() => assertRecentReauth(null, TEN_MINUTES, now)).toThrow(AuthorizationError)
    expect(() => assertRecentReauth(undefined, Number.MAX_SAFE_INTEGER, now)).toThrow(AuthorizationError)
  })

  it('tells the client to ask for a fresh sign-in', () => {
    expect(() => assertRecentReauth(null, TEN_MINUTES, now)).toThrow(expect.objectContaining({ status: 403, code: 'reauth_required' }))
  })

  it('defaults to ten minutes', () => {
    expect(STEP_UP_MAX_AGE_MS).toBe(TEN_MINUTES)
    expect(() => assertRecentReauth({ reauth_at: ago(TEN_MINUTES - 1000) }, undefined, now)).not.toThrow()
    expect(() => assertRecentReauth({ reauth_at: ago(TEN_MINUTES + 1000) }, undefined, now)).toThrow()
  })
})

describe('assertStepUp', () => {
  const session = (reauth_at: Date | null): Actor => ({ id: 'u1', role: 'admin', kind: 'session', reauth_at })

  it('lets a session through that confirmed it is the person within ten minutes', () => {
    expect(() => assertStepUp(session(ago(TEN_MINUTES - 1000)), now)).not.toThrow()
  })

  it('asks a stale session to confirm again', () => {
    expect(() => assertStepUp(session(ago(TEN_MINUTES + 1000)), now)).toThrow(expect.objectContaining({ status: 403, code: 'reauth_required' }))
    expect(() => assertStepUp(session(null), now)).toThrow(expect.objectContaining({ code: 'reauth_required' }))
  })

  it('always refuses API keys, even with a fresh time set', () => {
    const key: Actor = { ...session(now), kind: 'api_key', api_key_id: 'k1' }
    expect(() => assertStepUp(key, now)).toThrow(AuthorizationError)
    expect(() => assertStepUp(key, now)).toThrow(expect.objectContaining({ code: 'forbidden' }))
  })
})

describe('assertFreshAuthTime', () => {
  const started = ago(60_000)
  const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

  it('accepts a provider sign-in made after the re-authentication started', () => {
    expect(() => assertFreshAuthTime(seconds(ago(10_000)), started, now)).not.toThrow()
    // A provider clock a little behind ours.
    expect(() => assertFreshAuthTime(seconds(ago(90_000)), started, now)).not.toThrow()
  })

  it('refuses an older sign-in, a missing time and one in the future', () => {
    for (const auth_time of [seconds(ago(10 * 60_000)), undefined, Number.NaN, seconds(new Date(now.getTime() + 5 * 60_000))]) {
      expect(() => assertFreshAuthTime(auth_time, started, now)).toThrow(AuthenticationError)
    }
    expect(() => assertFreshAuthTime(undefined, started, now)).toThrow(expect.objectContaining({ code: 'reauth_stale' }))
  })
})
