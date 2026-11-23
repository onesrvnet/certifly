/**
 * Hold requests that arrive while the process is still migrating the database.
 * Health probes answer right away (/_ready reports not ready until then), so an
 * orchestrator does not kill an instance that is waiting for its database.
 */
export default defineEventHandler(async (event) => {
  if (migrationsDone() || event.path === '/_health' || event.path.startsWith('/_ready')) return
  await migrationsReady()
})
