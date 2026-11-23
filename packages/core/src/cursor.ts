import { type AnyColumn, type SQL, and, or, sql } from 'drizzle-orm'
import { ValidationError } from './errors'

/**
 * Keyset pagination. A list orders by a few sort keys that end in a unique one (the
 * id); the cursor holds the keys of the last row returned, and the next page starts
 * after it. Unlike offsets, rows created or moved meanwhile are neither skipped nor
 * repeated. The database reports the keys itself (`keys` below), so they compare
 * exactly as it sorts, collation and timestamp precision included.
 */
export interface SortKey {
  /** Never null: wrap nullable columns in `coalesce`. */
  expr: SQL | AnyColumn
  /** Postgres type the cursor value is cast to when compared. */
  type: 'timestamptz' | 'text' | 'boolean' | 'uuid' | 'double precision' | 'bigint'
  direction: 'asc' | 'desc'
}

export interface CursorInput {
  cursor?: string
  limit: number
}

export interface Paged<T> {
  rows: T[]
  next_cursor: string | null
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
/** As Postgres writes a timestamptz into JSON, e.g. `2026-11-22T12:00:00.123456+00:00`. */
const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?(Z|[+-](0\d|1[0-5])(:?[0-5]\d)?)?$/

/** A timestamp whose every field is in range (no 30 February), as Postgres requires. */
function isTimestamp(value: string): boolean {
  const match = TIMESTAMP.exec(value)
  if (!match) return false
  const [y, mo, d, h, mi, s] = match.slice(1, 7).map(Number) as [number, number, number, number, number, number]
  const date = new Date(Date.UTC(y, mo - 1, d, h, mi, s))
  return (
    y >= 1000 &&
    date.getUTCFullYear() === y &&
    date.getUTCMonth() === mo - 1 &&
    date.getUTCDate() === d &&
    date.getUTCHours() === h &&
    date.getUTCMinutes() === mi &&
    date.getUTCSeconds() === s
  )
}

const BIGINT_MAX = 9_223_372_036_854_775_807n

/**
 * Whether a cursor value can be cast to its key's type. Checked up front so that a tampered
 * cursor is a 400 and never reaches Postgres as a cast that fails.
 */
function fits(type: SortKey['type'], value: unknown): boolean {
  switch (type) {
    case 'uuid':
      return typeof value === 'string' && UUID.test(value)
    case 'timestamptz':
      return typeof value === 'string' && isTimestamp(value)
    case 'text':
      return typeof value === 'string' && !value.includes('\u0000')
    case 'boolean':
      return typeof value === 'boolean'
    case 'double precision':
      return typeof value === 'number' && Number.isFinite(value)
    case 'bigint':
      if (typeof value === 'number') return Number.isSafeInteger(value)
      return typeof value === 'string' && /^-?\d{1,19}$/.test(value) && BigInt(value) <= BIGINT_MAX && BigInt(value) >= -BIGINT_MAX - 1n
  }
}

function decode(cursor: string, sortKeys: SortKey[]): unknown[] {
  try {
    const values = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'))
    if (Array.isArray(values) && values.length === sortKeys.length && sortKeys.every((key, i) => fits(key.type, values[i]))) return values
  } catch {
    // Reported below.
  }
  throw new ValidationError('cursor: not a cursor from this list', 'invalid_cursor')
}

const value = (key: SortKey, raw: unknown) => sql`cast(${raw} as ${sql.raw(key.type)})`

/** Order, filter and key column for one page of a keyset-paginated query. */
export function keyset(sortKeys: SortKey[], input: CursorInput) {
  const after = input.cursor ? decode(input.cursor, sortKeys) : null
  let where: SQL | undefined
  if (after) {
    where = or(
      ...sortKeys.map((key, i) =>
        and(
          ...sortKeys.slice(0, i).map((earlier, j) => sql`${earlier.expr} = ${value(earlier, after[j])}`),
          sql`${key.expr} ${sql.raw(key.direction === 'asc' ? '>' : '<')} ${value(key, after[i])}`,
        ),
      ),
    )
  }
  return {
    where,
    orderBy: sortKeys.map((key) => sql`${key.expr} ${sql.raw(key.direction)}`),
    /** Select this as `cursor_keys`; `paged` turns it into `next_cursor`. */
    keys: sql<unknown[]>`json_build_array(${sql.join(
      sortKeys.map((key) => key.expr),
      sql`, `,
    )})`,
    /** One row more than asked, to know whether another page follows. */
    limit: input.limit + 1,
  }
}

/** Cut the extra row off and derive the next page's cursor from the last row kept. */
export function paged<T extends { cursor_keys: unknown[] }>(rows: T[], limit: number): Paged<Omit<T, 'cursor_keys'>> {
  const more = rows.length > limit
  const kept = more ? rows.slice(0, limit) : rows
  const last = kept.at(-1)
  return {
    rows: kept.map(({ cursor_keys: _, ...row }) => row),
    next_cursor: more && last ? Buffer.from(JSON.stringify(last.cursor_keys)).toString('base64url') : null,
  }
}

/** Alphabetical by a name, case-insensitively, then by id. */
export function byName(name: AnyColumn, id: AnyColumn): SortKey[] {
  return [
    { expr: sql`lower(${name})`, type: 'text', direction: 'asc' },
    { expr: id, type: 'uuid', direction: 'asc' },
  ]
}
