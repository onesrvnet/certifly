/** Liveness: the process answers. Does not look at the database, so waiting for it is not a failure. */
export default defineEventHandler(() => ({ status: 'ok' }))
