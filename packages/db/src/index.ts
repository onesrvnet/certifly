import type { PostgresJsDatabase } from 'drizzle-orm/postgres-js'
import type postgres from 'postgres'
import * as schema from './schema'

/**
 * The Drizzle database that core runs on. The web app creates it through NuxtHub (`db` from
 * `@nuxthub/db`), which owns the connection and the migrations; this type is what core
 * needs from it, so core stays free of any framework.
 */
export type Database = PostgresJsDatabase<typeof schema> & { $client: postgres.Sql }

export { schema }
export type { StoredNameConstraints } from './schema/cas'
export type { AlertChannelConfig, AlertRuleFilter } from './schema/alerts'
export type { LeafExtendedKeyUsage, LeafKeyAlgorithm, LeafKeyUsage, SanKind, StoredSan, SubjectField } from './schema/certificates'

export type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0]

/** Anything queries can run on: the database or an open transaction. */
export type Executor = Database | Transaction
