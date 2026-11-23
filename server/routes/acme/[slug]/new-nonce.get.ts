/**
 * ACME new nonce (GET)
 *
 * `GET /acme/<template-slug>/new-nonce`: a fresh replay nonce in the `Replay-Nonce` header, with
 * status 204 (RFC 8555 §7.2).
 */
export default defineAcmeNewNonce(204)
