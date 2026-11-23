import { estCaCertificates, estCertificatesBody } from '@certifly/core/est'

/**
 * EST: CA certificates
 *
 * `GET /.well-known/est/<template-slug>/cacerts` (RFC 7030 §4.1): the chain of the template's
 * issuing CA as a certs-only PKCS#7, base64. Public, no sign-in. 404 unless the template is
 * active and allows EST.
 */
export default defineEstHandler(async (event, template) => {
  const chain = await estCaCertificates(useContext(), template)
  return sendEstCertificates(event, estCertificatesBody(chain), { smime: false, cache: true })
})
