/**
 * ACME authorization
 *
 * `POST /acme/<template-slug>/authz/<id>`: an authorization and its challenges, as a POST-as-GET,
 * or `{"status":"deactivated"}` to give it up (RFC 8555 §7.5).
 */
export default defineAcmePost('authorization')
