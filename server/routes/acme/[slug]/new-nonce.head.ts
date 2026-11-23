/**
 * ACME new nonce (HEAD)
 *
 * `HEAD /acme/<template-slug>/new-nonce`: a fresh replay nonce in the `Replay-Nonce` header
 * (RFC 8555 §7.2). Every other ACME response carries one too.
 */
export default defineAcmeNewNonce(200)
