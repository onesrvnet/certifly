import { runJob, SCHEDULES } from '@certifly/core/jobs'

/**
 * Start the background roles this process is configured for (SERVICES=web,worker,cron) and
 * shut them down cleanly: stop taking jobs and close the queue's connections.
 */
export default defineNitroPlugin((nitroApp) => {
  const worker = hasService('worker')
  const cron = hasService('cron')
  if (worker || cron) {
    // Jobs touch the database, so wait until its schema is current.
    void (async () => {
      await migrationsReady()
      const queue = await useQueue()
      if (worker) await queue.work((job) => runJob(useContext(), job))
      if (cron) await queue.schedule(SCHEDULES)
    })().catch((error) => logServerError('[jobs] failed to start the worker', error))
  }

  nitroApp.hooks.hook('close', async () => {
    await stopJobs()
  })
})
