import { randomUUID } from 'node:crypto'
import type { H3Event } from 'h3'
import type { z } from 'zod'
import { AppError, ValidationError } from '@certifly/core/errors'

/** Error response body of every endpoint. */
export interface ApiErrorBody {
  error: { code: string; message: string; error_id?: string; details?: Record<string, unknown> }
}

const failure = (code: string, message: string, error_id?: string, details?: Record<string, unknown>): ApiErrorBody => ({
  error: { code, message, ...(error_id && { error_id }), ...(details && { details }) },
})

/**
 * Define an API endpoint (`POST /api/v2/<resource>/<action>`): validates the body,
 * runs the handler and maps domain errors to `{ error: { code, message } }` responses.
 * Unexpected errors are logged with a short id that the response carries as `error_id`,
 * so a report from the error page can be matched to the log.
 */
export function defineRpc<S extends z.ZodType, R>(
  bodySchema: S,
  handler: (event: H3Event, body: z.infer<S>) => Promise<R>,
) {
  return defineEventHandler(async (event): Promise<R> => {
    try {
      if ((await readCappedBody(event, MAX_API_BODY_BYTES)) === null) throw new AppError(413, 'payload_too_large', 'The request is too large')
      const raw = (await readBody(event).catch(() => undefined)) ?? {}
      const parsed = bodySchema.safeParse(raw)
      if (!parsed.success) {
        const issue = parsed.error.issues[0]
        throw new ValidationError(issue ? `${issue.path.join('.') || 'body'}: ${issue.message}` : undefined)
      }
      return await handler(event, parsed.data)
    } catch (error) {
      if (error instanceof AppError) {
        setResponseStatus(event, error.status)
        // Error bodies are excluded from the inferred response type: clients receive
        // them as a rejected $fetch with this payload in `error.data`.
        return failure(error.code, error.message, undefined, error.details) as never
      }
      if (isError(error) && error.statusCode === 429) {
        setResponseStatus(event, 429)
        return failure('rate_limited', error.statusMessage ?? 'Too many requests') as never
      }
      if (isError(error) && error.statusCode < 500) throw error
      const errorId = randomUUID().slice(0, 8)
      logServerError(`[rpc] ${event.path} failed (error ${errorId})`, error, { errorId, path: event.path })
      setResponseStatus(event, 500)
      return failure('internal', 'Something went wrong', errorId) as never
    }
  })
}
