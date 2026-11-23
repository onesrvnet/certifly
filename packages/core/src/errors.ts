/**
 * Error carrying an HTTP status and a stable machine-readable code for API responses.
 * `details` holds structured, non-secret context the client can show, such as every problem
 * found in an imported certificate.
 */
export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = new.target.name
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Invalid request', code = 'validation_error', details?: Record<string, unknown>) {
    super(400, code, message, details)
  }
}

/**
 * Codes: authentication_required, invalid_token (link), invalid_code (sign-in code),
 * account_deactivated, passkey_invalid, reauth_mismatch (another account at the identity
 * provider), reauth_stale (the provider did not confirm a fresh sign-in).
 */
export class AuthenticationError extends AppError {
  constructor(message = 'Authentication required', code = 'authentication_required') {
    super(401, code, message)
  }
}

/**
 * Codes: forbidden, invite_required, setup_token_required, setup_token_invalid,
 * reauth_required, email_disabled (the instance cannot send mail), token_setup_unavailable
 * (no setup token, or setup goes by email).
 */
export class AuthorizationError extends AppError {
  constructor(message = 'You do not have permission to do that', code = 'forbidden') {
    super(403, code, message)
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found', code = 'not_found') {
    super(404, code, message)
  }
}

/**
 * The request is fine but clashes with the current state. Codes: conflict, last_admin,
 * user_exists, passkey_exists, setup_email_mismatch, slug_taken, ca_not_active, parent_not_active, ca_disabled,
 * not_externally_signed, certificate_already_installed.
 */
export class ConflictError extends AppError {
  constructor(message = 'This conflicts with the current state', code = 'conflict', details?: Record<string, unknown>) {
    super(409, code, message, details)
  }
}

export class RateLimitError extends AppError {
  constructor(message = 'Too many requests, try again later') {
    super(429, 'rate_limited', message)
  }
}

/** Whether a database error is a unique violation (of `constraint`, when given). */
export function isUniqueViolation(error: unknown, constraint?: string): boolean {
  // Drizzle wraps the driver's error and keeps it as the cause.
  for (let e = error as { code?: unknown; constraint_name?: unknown; cause?: unknown } | undefined, depth = 0; e && depth < 3; e = e.cause as typeof e, depth++) {
    if (e.code === '23505') return !constraint || e.constraint_name === constraint
  }
  return false
}
