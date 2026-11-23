import { describe, expect, it } from 'vitest'
import '../src/reflect'

// The functions reflect-metadata needs when it finds this shim already installed and adopts it
// as a fallback provider (its CreateFallbackProvider), plus the ones tsyringe calls.
type Metadata = {
  defineMetadata(key: unknown, value: unknown, target: object, property?: PropertyKey): void
  hasOwnMetadata(key: unknown, target: object, property?: PropertyKey): boolean
  getOwnMetadata(key: unknown, target: object, property?: PropertyKey): unknown
  getMetadata(key: unknown, target: object, property?: PropertyKey): unknown
  getOwnMetadataKeys(target: object, property?: PropertyKey): unknown[]
  getMetadataKeys(target: object, property?: PropertyKey): unknown[]
  deleteMetadata(key: unknown, target: object, property?: PropertyKey): boolean
}

describe('Reflect metadata shim', () => {
  const R = Reflect as unknown as Metadata

  it('provides the whole metadata API, so a polyfill loaded later can adopt it', () => {
    for (const name of ['defineMetadata', 'hasOwnMetadata', 'getOwnMetadata', 'getMetadata', 'getOwnMetadataKeys', 'getMetadataKeys', 'deleteMetadata'] as const) {
      expect(typeof R[name]).toBe('function')
    }
  })

  it('stores, inherits, lists and deletes metadata', () => {
    class Base {}
    class Child extends Base {}
    R.defineMetadata('a', 1, Base)
    R.defineMetadata('b', 2, Child)
    R.defineMetadata('c', 3, Child, 'method')
    expect(R.getMetadata('a', Child)).toBe(1)
    expect(R.getOwnMetadata('a', Child)).toBeUndefined()
    expect(R.getOwnMetadataKeys(Child)).toEqual(['b'])
    expect(R.getMetadataKeys(Child)).toEqual(['b', 'a'])
    expect(R.getOwnMetadataKeys(Child, 'method')).toEqual(['c'])
    expect(R.deleteMetadata('b', Child)).toBe(true)
    expect(R.deleteMetadata('b', Child)).toBe(false)
    expect(R.hasOwnMetadata('b', Child)).toBe(false)
  })
})
