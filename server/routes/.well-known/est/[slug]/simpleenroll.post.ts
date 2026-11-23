import { authenticateEstCredential, estCertificatesBody, estEnroll } from '@certifly/core/est'
import { AuthenticationError } from '@certifly/core/errors'

/**
 * EST: enroll
 *
 * `POST /.well-known/est/<template-slug>/simpleenroll` (RFC 7030 §4.2.1): a base64 PKCS#10
 * request in, the new certificate out as a certs-only PKCS#7, base64. Authenticated with HTTP
 * basic credentials created for this template (`est_credentials.create`). Issued with the
 * template's rules, like any other certificate.
 */
export default defineEstHandler(async (event, template) => {
  const ctx = useContext()
  const { username, password } = basicCredentials(event)
  const credential = await authenticateEstCredential(ctx, template, username, password)
  if (!credential) throw new AuthenticationError('Authentication required')
  const result = await estEnroll(ctx, template, credential, { body: await estRequestBody(event), ip: requestIp(event) })
  return sendEstCertificates(event, estCertificatesBody([result.certificate.certificate_der]), { smime: true, cache: false })
})
