import { PgBoss, type QueueOptions } from 'pg-boss'
import { ALERT_DELIVERY_RETRIES } from './alerts'
import { JOB_NAMES, type Job, type JobName, type JobQueue } from './jobs'

export interface PgBossQueueOptions {
  connection_string: string
  /** Postgres schema for pg-boss's own tables; it creates and migrates it itself. */
  schema?: string
  /** Called with errors the queue cannot throw to a caller, such as lost connections. */
  on_error?: (error: Error) => void
}

const RETRIES = { retryLimit: 5, retryDelay: 10, retryBackoff: true } satisfies QueueOptions

/**
 * Per-queue settings. Mail jobs carry the mail itself, invite links included, so they must not
 * stay in the table: a sent mail's job is deleted by the worker straight away, and whatever
 * the worker does not delete is swept soon after. In pg-boss, `deleteAfterSeconds` counts from
 * when a job completed or failed for good (0 would turn this off), and `retentionSeconds` from
 * when a job became due, for jobs that never got that far.
 */
const QUEUES: Record<JobName, { options: QueueOptions; delete_when_done: boolean }> = {
  'mail.send': { options: { ...RETRIES, deleteAfterSeconds: 60, retentionSeconds: 30 * 60 }, delete_when_done: true },
  'cleanup.expired': { options: RETRIES, delete_when_done: false },
  'crls.rebuild_due': { options: RETRIES, delete_when_done: false },
  'ca_keys.rewrap': { options: RETRIES, delete_when_done: false },
  'crls.rebuild': { options: RETRIES, delete_when_done: false },
  'alerts.event': { options: RETRIES, delete_when_done: false },
  // Receivers can be down for a while: the delays double from about a minute, so the retries
  // span half an hour to an hour. core counts the attempts and marks the delivery failed after the last.
  'alerts.deliver': { options: { retryLimit: ALERT_DELIVERY_RETRIES, retryDelay: 60, retryBackoff: true, retryDelayMax: 3600 }, delete_when_done: false },
  'alerts.scan_expiry': { options: RETRIES, delete_when_done: false },
  // Validation records its own failures; a retry only covers a crash. The wait for a slow client is its own timeout.
  'acme.validate_challenge': { options: { retryLimit: 2, retryDelay: 5, retryBackoff: true }, delete_when_done: false },
}

/**
 * How often pg-boss sweeps each queue for jobs past those limits. Its default is once a day,
 * which would keep a finished mail job for up to a day.
 */
const MAINTENANCE_INTERVAL_SECONDS = 5 * 60

/**
 * A job queue kept in Postgres by pg-boss, so no extra service is needed. One queue per
 * job name; failed jobs are retried a few times with growing delays.
 */
export async function createPgBossQueue(options: PgBossQueueOptions): Promise<JobQueue> {
  const boss = new PgBoss({
    connectionString: options.connection_string,
    schema: options.schema ?? 'pgboss',
    maintenanceIntervalSeconds: MAINTENANCE_INTERVAL_SECONDS,
  })
  const onError = options.on_error ?? console.error
  boss.on('error', (error) => onError(error))
  await boss.start()
  for (const name of JOB_NAMES) {
    const { options: queueOptions } = QUEUES[name]
    // createQueue leaves a queue that already exists as it is, so apply the settings again.
    await boss.createQueue(name, queueOptions)
    await boss.updateQueue(name, queueOptions)
  }

  return {
    async send(job: Job, sendOptions = {}) {
      await boss.send(job.name, job.data, sendOptions.delay_seconds ? { startAfter: sendOptions.delay_seconds } : {})
    },

    async work(run, workOptions = {}) {
      for (const name of JOB_NAMES) {
        await boss.work<Job['data']>(name, { localConcurrency: workOptions.concurrency ?? 5 }, async (jobs) => {
          for (const job of jobs) {
            await run({ name, data: job.data } as Job)
            if (!QUEUES[name].delete_when_done) continue
            // The job is done; failing to delete it must not fail it, or it would run again.
            // The retention sweep removes it later instead.
            await boss.deleteJob(name, job.id).catch((error: Error) => onError(error))
          }
        })
      }
    },

    async schedule(schedules: readonly { name: JobName; cron: string }[]) {
      for (const { name, cron } of schedules) await boss.schedule(name, cron, {})
    },

    async stop() {
      await boss.stop({ graceful: true })
    },
  }
}
