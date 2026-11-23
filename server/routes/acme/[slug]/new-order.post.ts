/**
 * ACME new order
 *
 * `POST /acme/<template-slug>/new-order`: asks for a certificate for a list of dns and ip identifiers
 * (RFC 8555 §7.4, RFC 8738). Every identifier must be allowed by the template, wildcards excepted.
 * Each gets an authorization with http-01 and tls-alpn-01 challenges.
 */
export default defineAcmePost('new_order')
