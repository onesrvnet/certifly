import { publicKeyCrl } from '@certifly/core/crls'

/**
 * The CRL of one CA key
 *
 * `GET /api/pki/crl/<slug>/<key-id>.crl`: the CRL signed by one key of the CA, DER-encoded
 * (`application/pkix-crl`). This is the URL certificates carry in their CRL distribution points:
 * it stays right for them after the CA renews with a new key, and is published until the last
 * certificate that key signed has expired. Public, no sign-in.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = caSlug(getRouterParam(event, 'slug'))
  const keyId = keyIdFromFile(getRouterParam(event, 'file'), '.crl')
  const crl = slug && keyId ? await publicKeyCrl(useContext(), slug, keyId) : null
  if (!crl) throw notFound()
  return sendPkiFile(event, crl.crl_der, { type: 'application/pkix-crl', filename: `${slug}-${keyId}.crl`, modified: crl.this_update, fresh_until: crl.next_update })
})
