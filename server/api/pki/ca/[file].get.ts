import { publicCaCertificate } from '@certifly/core/cas'

/**
 * A CA certificate
 *
 * `GET /api/pki/ca/<slug>.crt`: the CA's active certificate, DER-encoded
 * (`application/pkix-cert`), as named in the AIA caIssuers of the certificates it issued.
 * Public, no sign-in.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = slugFromFile(getRouterParam(event, 'file'), '.crt')
  const cert = slug ? await publicCaCertificate(useContext(), slug) : null
  if (!cert) throw notFound()
  return sendPkiFile(event, cert.der, { type: 'application/pkix-cert', filename: `${slug}.crt`, modified: cert.updated_at })
})
