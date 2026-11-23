// tsyringe, which @peculiar/x509 uses internally, refuses to load without the Reflect metadata
// API. It only records constructor parameter types, and x509's classes take no parameters, so a
// small map-backed version of the calls it makes is enough and spares a polyfill dependency.
// A full polyfill loaded earlier (e.g. reflect-metadata) is left alone. One loaded later adopts
// whatever API it finds as a fallback provider, which needs the key listing and delete calls too,
// so the shim provides the whole metadata API, not just what tsyringe uses.

type MetadataReflect = typeof Reflect & {
  defineMetadata?: (key: unknown, value: unknown, target: object, property?: PropertyKey) => void
  getOwnMetadata?: (key: unknown, target: object, property?: PropertyKey) => unknown
  getMetadata?: (key: unknown, target: object, property?: PropertyKey) => unknown
  hasOwnMetadata?: (key: unknown, target: object, property?: PropertyKey) => boolean
  hasMetadata?: (key: unknown, target: object, property?: PropertyKey) => boolean
  getOwnMetadataKeys?: (target: object, property?: PropertyKey) => unknown[]
  getMetadataKeys?: (target: object, property?: PropertyKey) => unknown[]
  deleteMetadata?: (key: unknown, target: object, property?: PropertyKey) => boolean
  metadata?: (key: unknown, value: unknown) => (target: object, property?: PropertyKey) => void
}

const R = Reflect as MetadataReflect

if (typeof R.getMetadata !== 'function') {
  const store = new WeakMap<object, Map<PropertyKey | undefined, Map<unknown, unknown>>>()

  const table = (target: object, property: PropertyKey | undefined, create: boolean) => {
    let byProperty = store.get(target)
    if (!byProperty) {
      if (!create) return undefined
      byProperty = new Map()
      store.set(target, byProperty)
    }
    let entries = byProperty.get(property)
    if (!entries && create) {
      entries = new Map()
      byProperty.set(property, entries)
    }
    return entries
  }

  const lookup = (key: unknown, target: object, property?: PropertyKey): { found: boolean; value?: unknown } => {
    for (let t: object | null = target; t; t = Object.getPrototypeOf(t)) {
      const entries = table(t, property, false)
      if (entries?.has(key)) return { found: true, value: entries.get(key) }
    }
    return { found: false }
  }

  R.defineMetadata = (key, value, target, property) => void table(target, property, true)!.set(key, value)
  R.getOwnMetadata = (key, target, property) => table(target, property, false)?.get(key)
  R.hasOwnMetadata = (key, target, property) => table(target, property, false)?.has(key) ?? false
  R.getMetadata = (key, target, property) => lookup(key, target, property).value
  R.hasMetadata = (key, target, property) => lookup(key, target, property).found
  R.getOwnMetadataKeys = (target, property) => [...(table(target, property, false)?.keys() ?? [])]
  R.getMetadataKeys = (target, property) => {
    const keys = new Set<unknown>()
    for (let t: object | null = target; t; t = Object.getPrototypeOf(t)) for (const key of table(t, property, false)?.keys() ?? []) keys.add(key)
    return [...keys]
  }
  R.deleteMetadata = (key, target, property) => table(target, property, false)?.delete(key) ?? false
  R.metadata = (key, value) => (target, property) => R.defineMetadata!(key, value, target, property)
}

export {}
