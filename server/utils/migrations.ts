import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyDatabaseMigrations } from '@nuxthub/core/db'
import { db } from 'hub:db'

/**
 * Database migrations at startup, using NuxtHub's own runner, which keeps `_hub_migrations`
 * as the only tracking table. The image is built without database credentials, so they cannot
 * be applied during the build; instead every process runs the runner when it starts, under a
 * Postgres advisory lock so that replicas starting together apply each migration once. The
 * build copies the generated SQL next to the server (`<server>/db/migrations`), and the runner
 * reads it from there. Requests and background jobs wait for this to finish (see
 * `00.migrations.ts`); health probes do not, so an orchestrator keeps an instance that is
 * still waiting for its database.
 */

/** Arbitrary constant identifying the migration lock across replicas. */
const MIGRATION_LOCK_ID = 727_002

let pending: Promise<void> | undefined
let done = false

/** Where NuxtHub's runner finds `db/migrations`: its data directory in dev, the server output otherwise. */
function hubDir(): string {
  if (import.meta.dev) return useRuntimeConfig().hub.dir
  let dir = dirname(fileURLToPath(import.meta.url))
  for (let i = 0; i < 5; i++, dir = dirname(dir)) {
    if (existsSync(join(dir, 'db/migrations'))) return dir
  }
  throw new Error('The build contains no database migrations')
}

/** Wait until the database accepts connections, retrying with a growing delay (up to 5 s). */
async function waitForDatabase(timeoutMs: number) {
  const deadline = Date.now() + timeoutMs
  for (let attempt = 1, delay = 500; ; attempt++, delay = Math.min(delay * 2, 5000)) {
    try {
      await db.$client`select 1`
      return
    } catch (error) {
      if (Date.now() + delay > deadline) throw error
      console.warn(`[migrate] database not reachable yet (attempt ${attempt}: ${(error as Error).message}); retrying in ${delay} ms`)
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }
}

async function migrate() {
  await waitForDatabase(env().DATABASE_WAIT_SECONDS * 1000)
  // The lock belongs to a connection, so hold one connection for as long as the runner works.
  const lock = await db.$client.reserve()
  try {
    await lock`select pg_advisory_lock(${MIGRATION_LOCK_ID})`
    const applied = await applyDatabaseMigrations({ db: { dialect: 'postgresql' }, dir: hubDir() } as never, db)
    if (applied === false) throw new Error('Database migrations failed; see the log above')
  } finally {
    await lock`select pg_advisory_unlock(${MIGRATION_LOCK_ID})`.catch(() => {})
    lock.release()
  }
}

/** Apply database migrations once per process. Everything that touches the database waits on this. */
export function migrationsReady(): Promise<void> {
  pending ??= migrate().then(() => {
    done = true
  })
  return pending
}

export function migrationsDone(): boolean {
  return done
}
