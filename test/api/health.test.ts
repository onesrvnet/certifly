import { readdirSync } from 'node:fs'
import { setup } from '@nuxt/test-utils/e2e'
import { describe, expect, it } from 'vitest'
import { Client, query, serverOptions } from '../helpers'

describe('health and readiness', async () => {
  await setup(serverOptions)

  it('answers liveness without credentials', async () => {
    const response = await new Client().get('/_health')
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ status: 'ok' })
  })

  it('reports ready once migrations are applied and the database answers', async () => {
    const response = await new Client().get('/_ready')
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ status: 'ok', checks: { migrations: true, database: true } })
  })

  it('tracks migrations in NuxtHub’s table only', async () => {
    const applied = await query()`select name from _hub_migrations order by id`
    const files = readdirSync(new URL('../../server/db/migrations/postgresql', import.meta.url))
      .filter((name) => name.endsWith('.sql'))
      .map((name) => name.slice(0, -'.sql'.length))
      .sort()
    expect(applied.map((row) => row.name)).toEqual(files)
    const tables = await query()`select tablename from pg_tables where tablename like '%migrations%'`
    expect(tables.map((row) => row.tablename)).toEqual(['_hub_migrations'])
  })

  it('sends security headers', async () => {
    const response = await new Client().get('/_health')
    expect(response.headers.get('x-frame-options')).toBe('DENY')
    expect(response.headers.get('x-content-type-options')).toBe('nosniff')
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
  })

  it('serves the sign-in page', async () => {
    const response = await new Client().get('/login')
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('certifly')
  })
})
