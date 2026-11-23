import { createPgBossQueue } from '@certifly/core/jobs-pgboss'
import type { Job, JobQueue } from '@certifly/core/jobs'

let queue: Promise<JobQueue> | undefined

/** The job queue in Postgres (pg-boss), started on first use and shared by this process. */
export function useQueue(): Promise<JobQueue> {
  queue ??= createPgBossQueue({
    connection_string: env().DATABASE_URL,
    on_error: (error) => logServerError('[jobs] queue error', error),
  }).catch((error) => {
    queue = undefined
    throw error
  })
  return queue
}

/** Queue a background job; it runs on any process with the `worker` service. */
export function enqueueJob(job: Job): void {
  migrationsReady()
    .then(useQueue)
    .then((q) => q.send(job))
    .catch((error) => logServerError(`[jobs] failed to enqueue ${job.name}`, error, { job: job.name }))
}

/** Finish running jobs and close the queue's connections. */
export async function stopJobs() {
  const pending = queue
  queue = undefined
  await (await pending?.catch(() => undefined))?.stop()
}
