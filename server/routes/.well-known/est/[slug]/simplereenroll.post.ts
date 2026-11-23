import { AuthenticationError } from '@certifly/core/errors'
import { estCertificatesBody, estReenroll } from '@certifly/core/est'

/**
 * EST: re-enroll
 *
 * `POST /.well-known/est/<template-slug>/simplereenroll` (RFC 7030 §4.2.2): renews a
 * certificate. The device authenticates with its current certificate, which the TLS proxy in
 * front of certifly passes in the header named by `EST_CLIENT_CERT_HEADER`. Certificates are public,
 * so that header is only read when `TRUST_PROXY` is on, `EST_PROXY_SECRET` is set and the request
 * carries it in `EST_PROXY_SECRET_HEADER`; otherwise the answer is 401. The certificate must be
 * a current, unrevoked, unsuperseded one issued with this template, and the request must repeat
 * its subject and SANs. The old certificate becomes superseded.
 */
export default defineEstHandler(async (event, template) => {
  const header = trustedClientCertificateHeader(event)
  if (!header) throw new AuthenticationError('A client certificate is required')
  const result = await estReenroll(useContext(), template, { client_certificate: header, body: await estRequestBody(event), ip: requestIp(event) })
  return sendEstCertificates(event, estCertificatesBody([result.certificate.certificate_der]), { smime: true, cache: false })
})
