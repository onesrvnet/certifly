import { publicCrl } from '@certifly/core/crls'

/**
 * A CA's CRL
 *
 * `GET /api/pki/crl/<slug>.crl`: the current CRL of the CA, DER-encoded (`application/pkix-crl`),
 * as named in the CRL distribution points of the certificates it issued. Public, no sign-in.
 * Served for disabled CAs too, so relying parties keep checking what they issued.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = slugFromFile(getRouterParam(event, 'file'), '.crl')
  const crl = slug ? await publicCrl(useContext(), slug) : null
  if (!crl) throw notFound()
  return sendPkiFile(event, crl.crl_der, { type: 'application/pkix-crl', filename: `${slug}.crl`, modified: crl.this_update, fresh_until: crl.next_update })
})
