export type PkiErrorCode =
  | 'invalid_input'
  | 'invalid_pem'
  | 'invalid_certificate'
  | 'invalid_dn'
  | 'invalid_san'
  | 'invalid_name_constraints'
  | 'invalid_validity'
  | 'invalid_csr'
  | 'csr_signature_invalid'
  | 'unsupported_key'
  | 'issuer_not_ca'
  | 'issuer_expired'
  | 'path_length_exceeded'
  | 'validity_not_nested'
  | 'name_constraints_not_subset'
  | 'name_constraints_violation'
  | 'signer_mismatch'
  | 'invalid_crl'
  | 'invalid_password'
  | 'invalid_ssh_key'
  | 'invalid_ssh_certificate'
  | 'invalid_ssh_signature'
  | 'invalid_ssh_attestation'
  /** A well-formed attestation from an authenticator that is not a genuine Yubico one. */
  | 'untrusted_ssh_attestation'
  | 'ssh_key_encrypted'

/** A refusal with a stable code; `details` holds structured, non-secret context. */
export class PkiError extends Error {
  readonly code: PkiErrorCode
  readonly details?: Record<string, unknown>

  constructor(code: PkiErrorCode, message: string, details?: Record<string, unknown>) {
    super(message)
    this.name = 'PkiError'
    this.code = code
    this.details = details
  }
}
