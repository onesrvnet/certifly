import { validateAcmeChallenge } from './acme'
import { deliverAlert, dispatchEventAlerts, scanExpiryAlerts } from './alerts'
import type { Context } from './context'
import { rewrapCaKeys } from './ca-keys'
import { cleanupExpired } from './cleanup'
import { rebuildCaCrls, rebuildDueCrls } from './crls'

/**
 * Background jobs: serializable name + payload pairs, so they can be queued and
 * run by any worker process. Handlers must be safe to run again after a failure.
 */
export type Job =
  | { name: 'mail.send'; data: { to: string; subject: string; text: string; html?: string } }
  | { name: 'cleanup.expired'; data: Record<string, never> }
  | { name: 'crls.rebuild_due'; data: Record<string, never> }
  | { name: 'ca_keys.rewrap'; data: Record<string, never> }
  /** Rebuild every CRL of one CA now, e.g. after a revocation. */
  | { name: 'crls.rebuild'; data: { ca_id: string } }
  /** Match a stored audit event against the alert rules. */
  | { name: 'alerts.event'; data: { event_id: string } }
  /** Send one alert delivery; retried with backoff when it fails. */
  | { name: 'alerts.deliver'; data: { delivery_id: string } }
  | { name: 'alerts.scan_expiry'; data: Record<string, never> }
  /** Check an ACME challenge from outside after the client said it is ready. */
  | { name: 'acme.validate_challenge'; data: { challenge_id: string } }

export type JobName = Job['name']
export type EnqueueJob = (job: Job) => void

/** Every job name, e.g. to create a queue for each. */
export const JOB_NAMES = [
  'mail.send',
  'cleanup.expired',
  'crls.rebuild_due',
  'ca_keys.rewrap',
  'crls.rebuild',
  'alerts.event',
  'alerts.deliver',
  'alerts.scan_expiry',
  'acme.validate_challenge',
] as const satisfies readonly JobName[]

type Handlers = { [N in JobName]: (ctx: Context, data: Extract<Job, { name: N }>['data']) => Promise<unknown> }

const handlers: Handlers = {
  'mail.send': (ctx, data) => ctx.mailer.send(data),
  'cleanup.expired': (ctx) => cleanupExpired(ctx),
  'crls.rebuild_due': (ctx) => rebuildDueCrls(ctx),
  'ca_keys.rewrap': (ctx) => rewrapCaKeys(ctx),
  'crls.rebuild': (ctx, data) => rebuildCaCrls(ctx, data.ca_id),
  'alerts.event': (ctx, data) => dispatchEventAlerts(ctx, data.event_id),
  'alerts.deliver': (ctx, data) => deliverAlert(ctx, data.delivery_id),
  'alerts.scan_expiry': (ctx) => scanExpiryAlerts(ctx),
  'acme.validate_challenge': (ctx, data) => validateAcmeChallenge(ctx, data.challenge_id),
}

/** Jobs that run on a timetable (cron expressions, UTC), registered by the cron role. */
export const SCHEDULES: readonly { name: JobName; cron: string }[] = [
  { name: 'cleanup.expired', cron: '17 * * * *' },
  // CRLs enter their overlap window at least a day before they run out; every 15 minutes is plenty.
  { name: 'crls.rebuild_due', cron: '*/15 * * * *' },
  // After a master key rotation, moves every CA key to the new key within a day.
  { name: 'ca_keys.rewrap', cron: '41 3 * * *' },
  // Expiry warnings are counted in days; once a day, in the morning in Europe, is enough.
  { name: 'alerts.scan_expiry', cron: '7 6 * * *' },
]

/** Run a job in this process. */
export async function runJob(ctx: Context, job: Job): Promise<void> {
  const handler = handlers[job.name] as (ctx: Context, data: Job['data']) => Promise<unknown>
  if (!handler) throw new Error(`Unknown job: ${job.name}`)
  await handler(ctx, job.data)
}

/** Options for queueing one job. */
export interface SendOptions {
  /** Do not run before this many seconds have passed. */
  delay_seconds?: number
}

/**
 * Where jobs wait until a worker takes them. The server owns one: `jobs-pgboss.ts` keeps
 * them in Postgres, and tests can use any object that fits.
 */
export interface JobQueue {
  send(job: Job, options?: SendOptions): Promise<void>
  /** Start taking jobs from the queue and pass each to `run`. A thrown error fails the job, which is retried. */
  work(run: (job: Job) => Promise<void>, options?: { concurrency?: number }): Promise<void>
  /** Register recurring jobs. Safe to call from every instance. */
  schedule(schedules: readonly { name: JobName; cron: string }[]): Promise<void>
  /** Finish running jobs and close connections. */
  stop(): Promise<void>
}
