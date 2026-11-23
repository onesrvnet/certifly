import { readdir, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { fetch } from '@nuxt/test-utils/e2e'
import postgres from 'postgres'

export { serverOptions } from './build'

let sql: postgres.Sql | undefined

function db() {
  sql ??= postgres(process.env.DATABASE_URL!, { max: 1, onnotice: () => {} })
  return sql
}

/**
 * Remove all rows and sent mails so each test starts from an empty instance. NuxtHub's
 * `_hub_migrations` stays: a server that starts later must find its migrations applied.
 */
export async function resetState() {
  const tables = await db()`
    select tablename from pg_tables where schemaname = 'public' and tablename <> '_hub_migrations'`
  if (tables.length) {
    const statement = `truncate ${tables.map((t) => `"${t.tablename}"`).join(', ')} restart identity cascade`
    // Background work from the previous test (e.g. a job finishing) can still hold row locks;
    // Postgres resolves that as a deadlock, so retry.
    for (let attempt = 0; ; attempt++) {
      try {
        await db().unsafe(statement)
        break
      } catch (error) {
        if ((error as { code?: string }).code !== '40P01' || attempt >= 5) throw error
        await new Promise((resolve) => setTimeout(resolve, 100))
      }
    }
  }
  // Jobs left over from the previous test or file (e.g. an invite mail) must not run in this one.
  const [queue] = await db()`select to_regclass('pgboss.job') as name`
  if (queue?.name) await db().unsafe('delete from pgboss.job')
  await rm(process.env.MAIL_OUTBOX_DIR!, { recursive: true, force: true })
}

export function query() {
  return db()
}

/** Minimal HTTP client that keeps cookies between requests, like a browser. */
export class Client {
  constructor(private cookies = new Map<string, string>()) {}

  /** Call an RPC by name: `users.list` → POST /api/v2/users/list. */
  async rpc<T = any>(method: string, body: unknown = {}, headers: Record<string, string> = {}) {
    const response = await fetch(`/api/v2/${method.replaceAll('.', '/')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.headers(), ...headers },
      body: JSON.stringify(body),
    })
    this.store(response)
    return { status: response.status, headers: response.headers, body: (await response.json()) as T }
  }

  /** Like `rpc`, authenticated with an API key instead of the cookies. */
  rpcWithKey<T = any>(secret: string, method: string, body: unknown = {}) {
    return new Client().rpc<T>(method, body, { authorization: `Bearer ${secret}` })
  }

  async get(path: string) {
    const response = await fetch(path, { headers: this.headers(), redirect: 'manual' })
    this.store(response)
    return response
  }

  private headers(): Record<string, string> {
    return { cookie: this.cookieHeader() }
  }

  cookieHeader() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
  }

  private store(response: Response) {
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(';')
      const [name, ...value] = pair!.split('=')
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(header)) this.cookies.delete(name!)
      else this.cookies.set(name!, value.join('='))
    }
  }
}

export interface SentMail {
  to: string
  subject: string
  text: string
  html?: string
}

export async function sentMails(to?: string): Promise<SentMail[]> {
  const dir = process.env.MAIL_OUTBOX_DIR!
  const files = await readdir(dir).catch(() => [] as string[])
  const mails = await Promise.all(files.sort().map(async (f) => JSON.parse(await readFile(join(dir, f), 'utf8')) as SentMail))
  return to ? mails.filter((m) => m.to === to.toLowerCase()) : mails
}

/** Wait for a mail to an address (invites go through the job queue, so they arrive a moment later). */
export async function waitForMail(to: string, match: (mail: SentMail) => boolean = () => true, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const mail = (await sentMails(to)).filter(match).at(-1)
    if (mail) return mail
    if (Date.now() > deadline) throw new Error(`No mail arrived for ${to}`)
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
}

/** Extract the code and link token from the latest sign-in mail sent to an address. */
export async function latestSigninMail(to: string) {
  const mail = (await sentMails(to)).at(-1)
  if (!mail) throw new Error(`No mail sent to ${to}`)
  const code = mail.subject.match(/code: (\d{6})/)?.[1]
  const token = mail.text.match(/token=([\w-]+)/)?.[1]
  return { mail, code: code!, token: token! }
}

/** Run initial setup and return a signed-in client for the first (admin) user. */
export async function setupAdmin(email = 'admin@example.com') {
  const client = new Client()
  await client.rpc('sign_in_codes.create', { email })
  const { token } = await latestSigninMail(email)
  await client.rpc('sign_in_codes.verify', { token })
  return client
}

/** Sign in an existing (or invited) user through the email code flow. */
export async function signInWithCode(email: string) {
  const client = new Client()
  await client.rpc('sign_in_codes.create', { email })
  const { code } = await latestSigninMail(email)
  const result = await client.rpc('sign_in_codes.verify', { email, code })
  return { client, result }
}

/** An admin invites `email` with `role`; returns a client signed in as that person via the invite link. */
export async function addUser(admin: Client, email: string, role: 'admin' | 'operator' | 'viewer') {
  const created = await admin.rpc('invites.create', { email, role })
  if (created.status !== 200) throw new Error(`invite failed: ${JSON.stringify(created.body)}`)
  const mail = await waitForMail(email, (m) => /token=/.test(m.text))
  const token = mail.text.match(/token=([\w-]+)/)![1]!
  const client = new Client()
  const accepted = await client.rpc('invite_acceptances.create', { token })
  if (accepted.status !== 200) throw new Error(`accept failed: ${JSON.stringify(accepted.body)}`)
  return client
}

/** Pretend every session last confirmed who the person is `minutes` ago. */
export function ageSessions(minutes: number) {
  return query()`update sessions set reauth_at = now() - make_interval(mins => ${minutes})`
}

/** Confirm again with an emailed code, so sensitive actions are open for ten minutes. */
export async function confirmWithCode(client: Client, email: string) {
  const started = await client.rpc('reauthentications.create', { method: 'email' })
  if (started.status !== 200) throw new Error(`re-authentication failed: ${JSON.stringify(started.body)}`)
  const { code } = await latestSigninMail(email)
  const verified = await client.rpc('reauthentications.verify', { method: 'email', code })
  if (verified.status !== 200) throw new Error(`re-authentication failed: ${JSON.stringify(verified.body)}`)
}

/** The id of the person a client is signed in as. */
export async function userId(client: Client): Promise<string> {
  return (await client.rpc('sessions.get')).body.data.user.id
}

/** Poll `check` until it returns something truthy, e.g. a job's result showing up in the database. */
export async function waitFor<T>(check: () => Promise<T | null | undefined | false>, what: string, timeoutMs = 15_000): Promise<T> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await check()
    if (value) return value
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${what}`)
    await new Promise((resolve) => setTimeout(resolve, 150))
  }
}

/**
 * core run directly against the test database, as a worker or the cron role would. `jobs`
 * collects what it queues instead of sending it to pg-boss.
 */
export async function coreContext() {
  const [{ drizzle }, { schema }, { LocalKeyProvider, loadKeyvaultConfig }, { createMailer }] = await Promise.all([
    import('drizzle-orm/postgres-js'),
    import('@certifly/db'),
    import('@certifly/keyvault'),
    import('@certifly/core/mailer'),
  ])
  const sql = postgres(process.env.DATABASE_URL!, { max: 2, onnotice: () => {} })
  const db = drizzle(sql, { schema, casing: 'snake_case' })
  const config = await loadKeyvaultConfig({ master_key: process.env.CERTIFLY_MASTER_KEY!, session_secret: process.env.SECRET_KEY! })
  const jobs: { name: string; data: unknown }[] = []
  const ctx = {
    db,
    keys: new LocalKeyProvider(config),
    mailer: createMailer({ MAIL_OUTBOX_DIR: process.env.MAIL_OUTBOX_DIR }),
    base_url: process.env.URL!,
    pki_base_url: process.env.URL!,
    secret_key: process.env.SECRET_KEY!,
    emit: () => {},
    enqueue: (job: { name: string; data: unknown }) => void jobs.push(job),
  } as unknown as import('@certifly/core/context').Context
  return { ctx, jobs, close: () => sql.end() }
}
