import { cpSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyDatabaseMigrations, createDrizzleClient } from '@nuxthub/core/db'
import postgres from 'postgres'
import { buildServer } from './build'

const DEFAULT_SERVER = 'postgres://certifly:certifly@localhost:5432/certifly_test'

/**
 * Create and migrate a throwaway database for this test run, so concurrent runs
 * (e.g. two developers or agents on one machine) never truncate each other's data.
 * Set TEST_DATABASE_URL to reuse a fixed database instead (e.g. in CI).
 *
 * The schema comes from the migrations `nuxt db generate` wrote, applied by NuxtHub's own
 * runner (the one the server uses when it starts), so `_hub_migrations` is filled as in production.
 */
export default async function setup() {
  const fixed = process.env.TEST_DATABASE_URL
  const base = new URL(fixed ?? DEFAULT_SERVER)
  const name = fixed ? base.pathname.slice(1) : `certifly_test_${process.pid}_${Date.now().toString(36)}`
  const url = new URL(base)
  url.pathname = `/${name}`

  const adminUrl = new URL(base)
  adminUrl.pathname = '/postgres'
  const admin = postgres(adminUrl.toString(), { max: 1, onnotice: () => {} })
  const [exists] = await admin`select 1 from pg_database where datname = ${name}`
  if (!exists) await admin.unsafe(`create database "${name}"`)
  await admin.end()

  // The runner reads `<dir>/db/migrations`, as it does in the build output.
  const hubDir = mkdtempSync(join(tmpdir(), 'certifly-hub-'))
  mkdirSync(join(hubDir, 'db'), { recursive: true })
  // Only the SQL files, as NuxtHub copies them: drizzle's `meta` snapshots are not migrations.
  cpSync(fileURLToPath(new URL('../server/db/migrations', import.meta.url)), join(hubDir, 'db/migrations'), {
    recursive: true,
    filter: (src) => !src.endsWith('.json') && !src.endsWith('/meta'),
  })
  const db = await createDrizzleClient({ driver: 'postgres-js', connection: { url: url.toString() }, casing: 'snake_case' }, hubDir)
  const applied = await applyDatabaseMigrations({ db: { dialect: 'postgresql' }, dir: hubDir } as never, db)
  await db.$client?.end?.()
  rmSync(hubDir, { recursive: true, force: true })
  if (applied === false) throw new Error('The test database could not be migrated')

  const outbox = mkdtempSync(join(tmpdir(), 'certifly-mail-'))
  process.env.DATABASE_URL = url.toString()
  process.env.MAIL_OUTBOX_DIR = outbox
  process.env.URL ??= 'http://localhost:3000'
  process.env.SECRET_KEY ??= 'test-secret-key-test-secret-key-0000'
  process.env.CERTIFLY_MASTER_KEY ??= 'a1'.repeat(32)
  // The server waits for the database for up to this long; tests should fail fast instead.
  process.env.DATABASE_WAIT_SECONDS = '10'

  await buildServer()

  return async () => {
    rmSync(outbox, { recursive: true, force: true })
    if (fixed) return
    const cleanup = postgres(adminUrl.toString(), { max: 1, onnotice: () => {} })
    await cleanup.unsafe(`drop database if exists "${name}" with (force)`)
    await cleanup.end()
  }
}
