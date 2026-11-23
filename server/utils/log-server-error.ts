/**
 * Log an unexpected server error. Handlers that answer errors themselves (RPC, jobs) catch
 * them before Nitro's own hooks would see them, so they report here.
 */
export function logServerError(message: string, error: unknown, tags: Record<string, string> = {}) {
  console.error(message, error, Object.keys(tags).length ? tags : '')
}
