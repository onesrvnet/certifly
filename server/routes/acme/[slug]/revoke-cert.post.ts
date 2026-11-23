/**
 * ACME revoke certificate
 *
 * `POST /acme/<template-slug>/revoke-cert`: revokes a certificate this directory issued (RFC 8555
 * §7.6). Signed by the account that ordered it, or by the certificate's own key.
 */
export default defineAcmePost('revoke_cert')
