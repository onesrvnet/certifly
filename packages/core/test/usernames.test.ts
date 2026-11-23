import { describe, expect, it } from 'vitest'
import { checkUsername, deriveUsername, RESERVED_USERNAMES } from '../src/usernames'

describe('usernames', () => {
  it('derives a login from the local part of an email', () => {
    expect(deriveUsername('Alice@example.com')).toBe('alice')
    expect(deriveUsername('a.b-c_d@example.com')).toBe('a.b-c_d')
    expect(deriveUsername('first+tag@example.com')).toBe('first-tag')
    expect(deriveUsername('1stuser@example.com')).toBe('u1stuser')
    expect(deriveUsername('x'.repeat(50) + '@example.com')).toHaveLength(32)
  })

  it('never derives a system account name', () => {
    for (const name of RESERVED_USERNAMES) expect(RESERVED_USERNAMES.has(deriveUsername(`${name}@example.com`))).toBe(false)
    expect(deriveUsername('root@example.com')).toBe('root-1')
  })

  it('checks names an admin sets', () => {
    expect(checkUsername(' Alice ')).toBe('alice')
    for (const bad of ['', 'a b', '-lead', '9lives', 'x'.repeat(33), 'ünï']) expect(() => checkUsername(bad)).toThrow(/username|lowercase/)
    expect(() => checkUsername('root')).toThrow(/system account/)
  })
})
