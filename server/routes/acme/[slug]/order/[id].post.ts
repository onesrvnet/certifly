/**
 * ACME order
 *
 * `POST /acme/<template-slug>/order/<id>`: the state of an order, as a POST-as-GET (RFC 8555 §7.4).
 */
export default defineAcmePost('order')
