import { describe, expect, it } from 'vitest'
import { isUuid } from '../src/ids'

describe('isUuid', () => {
  it('accepts UUIDs in either case', () => {
    expect(isUuid('0b9a6d2e-3c61-4f0e-9a52-6f1f0f0d7a11')).toBe(true)
    expect(isUuid('0B9A6D2E-3C61-4F0E-9A52-6F1F0F0D7A11')).toBe(true)
  })

  it('rejects other strings and non-strings', () => {
    expect(isUuid('not-a-uuid')).toBe(false)
    expect(isUuid('0b9a6d2e3c614f0e9a526f1f0f0d7a11')).toBe(false)
    expect(isUuid(42)).toBe(false)
    expect(isUuid(null)).toBe(false)
  })
})
