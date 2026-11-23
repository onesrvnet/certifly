import { describe, expect, it } from 'vitest'
import { ConflictError } from '../src/errors'
import { assertAnotherAdmin } from '../src/users'

describe('assertAnotherAdmin', () => {
  it('refuses to demote or deactivate the last admin', () => {
    expect(() => assertAnotherAdmin(0)).toThrow(ConflictError)
    expect(() => assertAnotherAdmin(0)).toThrow(expect.objectContaining({ status: 409, code: 'last_admin' }))
  })

  it('allows it while another admin remains', () => {
    expect(() => assertAnotherAdmin(1)).not.toThrow()
    expect(() => assertAnotherAdmin(5)).not.toThrow()
  })
})
