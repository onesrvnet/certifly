import { describe, expect, it } from 'vitest'
import { schema } from '@certifly/db'
import { byName, keyset, paged } from '../src/cursor'
import { ValidationError } from '../src/errors'

const sortKeys = byName(schema.users.name, schema.users.id)
const encode = (keys: unknown) => Buffer.from(JSON.stringify(keys)).toString('base64url')

describe('paged', () => {
  const row = (n: number) => ({ n, cursor_keys: [`name ${n}`, `id-${n}`] })

  it('returns every row and no cursor when the list fits on one page', () => {
    const result = paged([row(1), row(2)], 3)
    expect(result.rows).toEqual([{ n: 1 }, { n: 2 }])
    expect(result.next_cursor).toBeNull()
  })

  it('cuts the extra row and points the cursor at the last row kept', () => {
    const result = paged([row(1), row(2), row(3)], 2)
    expect(result.rows).toEqual([{ n: 1 }, { n: 2 }])
    expect(JSON.parse(Buffer.from(result.next_cursor!, 'base64url').toString())).toEqual(['name 2', 'id-2'])
  })

  it('handles an empty list', () => {
    expect(paged([], 10)).toEqual({ rows: [], next_cursor: null })
  })
})

describe('keyset', () => {
  it('has no filter on the first page and asks for one row more than the limit', () => {
    const page = keyset(sortKeys, { limit: 25 })
    expect(page.where).toBeUndefined()
    expect(page.limit).toBe(26)
    expect(page.orderBy).toHaveLength(2)
  })

  it('filters after the cursor', () => {
    expect(keyset(sortKeys, { limit: 25, cursor: encode(['ann', '0b9a6d2e-3c61-4f0e-9a52-6f1f0f0d7a11']) }).where).toBeDefined()
  })

  it('rejects cursors that are not from this list', () => {
    for (const cursor of ['not a cursor', encode(['only one key']), encode('a string'), encode(['a', 'b', 'c'])]) {
      expect(() => keyset(sortKeys, { limit: 25, cursor })).toThrow(ValidationError)
    }
  })

  it('reports an invalid cursor with a stable code', () => {
    try {
      keyset(sortKeys, { limit: 25, cursor: 'x' })
      expect.unreachable()
    } catch (error) {
      expect((error as ValidationError).code).toBe('invalid_cursor')
    }
  })
})

describe('cursor values', () => {
  const byTime = [
    { expr: schema.events.created_at, type: 'timestamptz' as const, direction: 'desc' as const },
    { expr: schema.events.id, type: 'uuid' as const, direction: 'desc' as const },
  ]
  const id = '0b9a6d2e-3c61-4f0e-9a52-6f1f0f0d7a11'

  it('accepts values as the database writes them', () => {
    expect(() => keyset(byTime, { limit: 5, cursor: encode(['2026-11-22T12:00:00.123456+00:00', id]) })).not.toThrow()
    expect(() => keyset(sortKeys, { limit: 5, cursor: encode(['ann', id]) })).not.toThrow()
  })

  it('refuses values the database could not cast, so a tampered cursor is a 400 and not a 500', () => {
    for (const keys of [
      ['ann', 'not-a-uuid'],
      ['ann', 42],
      [7, id],
      ['ann\u0000', id],
    ]) {
      expect(() => keyset(sortKeys, { limit: 5, cursor: encode(keys) })).toThrow(expect.objectContaining({ code: 'invalid_cursor' }))
    }
    for (const time of ['yesterday', '2026-02-30T00:00:00+00:00', '2026-11-22T25:00:00+00:00', 1795348800000, null]) {
      expect(() => keyset(byTime, { limit: 5, cursor: encode([time, id]) })).toThrow(expect.objectContaining({ code: 'invalid_cursor' }))
    }
  })
})
