/**
 * ACME new account
 *
 * `POST /acme/<template-slug>/new-account`: registers an account key (RFC 8555 §7.3). The request must
 * carry an external account binding made with one of the template's binding keys; without one the
 * answer is `externalAccountRequired`. `onlyReturnExisting` looks an account up by its key.
 */
export default defineAcmePost('new_account')
