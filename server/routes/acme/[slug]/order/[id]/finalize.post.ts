/**
 * ACME finalize order
 *
 * `POST /acme/<template-slug>/order/<id>/finalize`: sends the CSR of a ready order (RFC 8555 §7.4).
 * Its names must be exactly the order's identifiers. The certificate is issued with the template's
 * rules, the same way as any other request.
 */
export default defineAcmePost('finalize')
