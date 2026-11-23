import { customType, timestamp, uuid } from 'drizzle-orm/pg-core'

export const id = () => uuid().primaryKey().defaultRandom()

export const timestamps = {
  created_at: timestamp({ withTimezone: true }).notNull().defaultNow(),
  updated_at: timestamp({ withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
}

/** Binary column (Postgres bytea) exposed as Uint8Array. */
export const bytea = customType<{ data: Uint8Array; driverData: Buffer }>({
  dataType: () => 'bytea',
  toDriver: (value) => Buffer.from(value),
  fromDriver: (value) => new Uint8Array(value),
})
