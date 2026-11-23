/**
 * The HTTP status of a failed request, whether it's our RpcError or the error type
 * useAsyncData wraps it in (which keeps the original as `cause`). Undefined if unknown.
 */
export function errorStatus(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined
  const { status, statusCode, cause } = error as { status?: unknown; statusCode?: unknown; cause?: unknown }
  if (cause instanceof RpcError && cause.status) return cause.status
  if (typeof status === 'number' && status) return status
  if (typeof statusCode === 'number' && statusCode) return statusCode
  return undefined
}

/** The RpcError behind an error, unwrapping useAsyncData's wrapper. */
function rpcErrorOf(error: unknown): RpcError | undefined {
  if (error instanceof RpcError) return error
  const cause = (error as { cause?: unknown } | null)?.cause
  return cause instanceof RpcError ? cause : undefined
}

/**
 * What the error page needs from a failed load: the status, the server's error id for
 * unexpected errors, and whether the server couldn't be reached at all.
 */
export function errorDetails(error: unknown): { status: number | undefined; errorId?: string; offline: boolean } {
  const rpc = rpcErrorOf(error)
  return { status: errorStatus(error), errorId: rpc?.errorId, offline: rpc?.code === 'network' }
}

/**
 * The error page for a page whose main data failed to load. `notFound` names the thing
 * (e.g. "Page not found"); access errors show it too, so they don't reveal existence.
 */
export function pageError(error: unknown, notFound: string) {
  const { status, errorId, offline } = errorDetails(error)
  if (offline) return createError({ statusCode: 503, statusMessage: 'Offline', fatal: true, data: { offline: true } })
  if (!status || status >= 500) return createError({ statusCode: status ?? 500, statusMessage: 'Server error', fatal: true, data: { errorId } })
  return createError({ statusCode: status === 403 ? 403 : 404, statusMessage: notFound, fatal: true, data: { title: notFound } })
}

/** Whether the server wants the person to confirm it is them again before this action. */
export function isReauthRequired(error: unknown) {
  return rpcErrorOf(error)?.code === 'reauth_required'
}
