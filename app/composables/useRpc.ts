import type { ApiErrorBody, RpcInput, RpcName, RpcOutput } from '~/types/api'

/** Error thrown by `useRpc` calls: `code` is the server's stable error code (or `network`/`unknown`). */
export class RpcError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    /** Set for unexpected server errors; the same id is in the server log. */
    readonly errorId?: string,
    /** Values for the translated message. */
    readonly params?: Record<string, string>,
    /** Structured context from the server, e.g. every problem found in an imported certificate. */
    readonly details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'RpcError'
  }
}

type FetchFailure = { name?: string; statusCode?: number; data?: Partial<ApiErrorBody> }

function toRpcError(error: unknown): RpcError {
  const failure = error as FetchFailure
  if (failure?.name !== 'FetchError') return new RpcError(0, 'unknown', String(error))
  const status = failure.statusCode ?? 0
  const body = failure.data?.error
  const code = typeof body?.code === 'string' ? body.code : status ? 'unknown' : 'network'
  const message = typeof body?.message === 'string' ? body.message : code
  const details = body?.details && typeof body.details === 'object' ? body.details : undefined
  return new RpcError(status, code, message, typeof body?.error_id === 'string' ? body.error_id : undefined, undefined, details)
}

/**
 * Typed caller for the API: `rpc('users.list')` posts to `/api/v2/users/list`. During SSR it
 * forwards the incoming request's cookies, so call it from setup, middleware or store setup
 * (inside the Nuxt context).
 */
export function useRpc() {
  // Typed per endpoint below; the generic route typing of $fetch is too deep for TS here.
  const fetcher = useRequestFetch() as (url: string, options: { method: 'POST'; body: object }) => Promise<unknown>
  return async function rpc<N extends RpcName>(name: N, ...[body]: {} extends RpcInput[N] ? [RpcInput[N]?] : [RpcInput[N]]) {
    try {
      return (await fetcher(`/api/v2/${name.replaceAll('.', '/')}`, { method: 'POST', body: body ?? {} })) as RpcOutput<N>
    } catch (error) {
      throw toRpcError(error)
    }
  }
}
