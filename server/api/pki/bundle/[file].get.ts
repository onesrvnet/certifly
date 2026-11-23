import { publicTrustBundle } from '@certifly/core/trust-bundles'

/**
 * A trust bundle
 *
 * `GET /api/pki/bundle/<slug>.pem`: the CA certificates of a trust bundle, PEM
 * (`application/pem-certificate-chain`), for client trust stores and mTLS `ca_file` settings.
 * Public, no sign-in, cacheable for an hour.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = slugFromFile(getRouterParam(event, 'file'), '.pem')
  const bundle = slug ? await publicTrustBundle(useContext(), slug) : null
  if (!bundle) throw notFound()
  return sendPkiFile(event, bundle.pem, { type: 'application/pem-certificate-chain', filename: `${slug}.pem`, modified: bundle.updated_at })
})
