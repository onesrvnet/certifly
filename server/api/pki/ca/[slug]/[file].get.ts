import { publicCaKeyCertificate } from '@certifly/core/cas'

/**
 * The certificate of one CA key
 *
 * `GET /api/pki/ca/<slug>/<key-id>.crt`: the newest certificate the CA holds for one of its keys,
 * DER-encoded (`application/pkix-cert`). Certificates carry this URL as AIA caIssuers, so it
 * still names the key that signed them after the CA renews with a new key. Public, no sign-in.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = caSlug(getRouterParam(event, 'slug'))
  const keyId = keyIdFromFile(getRouterParam(event, 'file'), '.crt')
  const cert = slug && keyId ? await publicCaKeyCertificate(useContext(), slug, keyId) : null
  if (!cert) throw notFound()
  return sendPkiFile(event, cert.der, { type: 'application/pkix-cert', filename: `${slug}-${keyId}.crt`, modified: cert.updated_at })
})
