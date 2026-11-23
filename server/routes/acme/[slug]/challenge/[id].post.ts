/**
 * ACME challenge
 *
 * `POST /acme/<template-slug>/challenge/<id>`: `{}` says the challenge is ready, and starts the
 * check from outside; an empty payload only reads it (RFC 8555 §7.5.1, §8).
 */
export default defineAcmePost('challenge')
