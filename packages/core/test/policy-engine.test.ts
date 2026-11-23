import { describe, expect, it } from 'vitest'
import { PolicySet } from '../src/policies/engine'

type Action = 'read' | 'write'
const policy = new PolicySet<{ id: number }, { owner: number }, Action>({
  read: () => true,
  write: (actor, subject) => actor.id === subject.owner,
})

describe('PolicySet', () => {
  it('evaluates the rule for an action', () => {
    expect(policy.can({ id: 1 }, 'write', { owner: 1 })).toBe(true)
    expect(policy.can({ id: 2 }, 'write', { owner: 1 })).toBe(false)
  })

  it('denies actions without a rule', () => {
    expect(policy.can({ id: 1 }, 'delete' as Action, { owner: 1 })).toBe(false)
  })

  it('lists the abilities of the registered actions', () => {
    expect(policy.abilities({ id: 2 }, { owner: 1 })).toEqual({ read: true, write: false })
  })
})
