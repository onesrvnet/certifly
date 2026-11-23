/** Readiness: migrations applied and Postgres reachable. */
export default defineEventHandler(async (event) => {
  const checks = {
    migrations: migrationsDone(),
    database: await useContext()
      .db.$client`select 1`.then(() => true)
      .catch(() => false),
  }
  const ready = Object.values(checks).every(Boolean)
  if (!ready) setResponseStatus(event, 503)
  return { status: ready ? 'ok' : 'unavailable', checks }
})
