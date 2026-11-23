/**
 * ACME directory
 *
 * `GET /acme/<template-slug>/directory`: where an ACME client starts (RFC 8555 §7.1.1). Lists the
 * endpoints of the template's ACME server and says that an external account binding is required.
 * 404 unless the template is active and allows ACME.
 */
export default defineAcmeDirectory()
