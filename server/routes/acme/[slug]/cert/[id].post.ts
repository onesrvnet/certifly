/**
 * ACME certificate
 *
 * `POST /acme/<template-slug>/cert/<id>`: the issued certificate and its chain as
 * `application/pem-certificate-chain`, as a POST-as-GET (RFC 8555 §7.4.2).
 */
export default defineAcmePost('certificate')
