import { AppError } from '@certifly/core/errors'

/**
 * For plain (non-RPC) routes: turn a domain error into an HTTP error with its status
 * and message. Anything else is returned unchanged, so it still surfaces as a 500.
 */
export function toHttpError(error: unknown): unknown {
  return error instanceof AppError ? createError({ statusCode: error.status, statusMessage: error.message }) : error
}
