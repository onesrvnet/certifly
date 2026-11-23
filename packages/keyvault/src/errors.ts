export type KeyvaultErrorCode =
  | 'invalid_config'
  | 'invalid_binding'
  | 'invalid_record'
  | 'unknown_kek'
  | 'decrypt_failed'
  | 'unsupported_algorithm'
  | 'key_mismatch'

/** Errors carry a stable code and a short message that never contains key material. */
export class KeyvaultError extends Error {
  readonly code: KeyvaultErrorCode

  constructor(code: KeyvaultErrorCode, message: string) {
    super(message)
    this.name = 'KeyvaultError'
    this.code = code
  }
}
