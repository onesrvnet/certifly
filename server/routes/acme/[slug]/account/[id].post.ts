/**
 * ACME account
 *
 * `POST /acme/<template-slug>/account/<id>`: reads an account (empty payload), updates its contact
 * or deactivates it (RFC 8555 §7.3.2, §7.3.6). Only the account itself may.
 */
export default defineAcmePost('account')
