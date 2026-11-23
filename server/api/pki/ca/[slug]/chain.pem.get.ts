import { publicCaChain } from '@certifly/core/cas'

/**
 * A CA certificate with its chain
 *
 * `GET /api/pki/ca/<slug>/chain.pem`: the CA's active certificate followed by its issuers up to
 * the root, PEM (`application/pem-certificate-chain`, RFC 8555 §9.1). Public, no sign-in.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = caSlug(getRouterParam(event, 'slug'))
  const chain = slug ? await publicCaChain(useContext(), slug) : null
  if (!chain) throw notFound()
  return sendPkiFile(event, chain.pem, { type: 'application/pem-certificate-chain', filename: `${slug}-chain.pem`, modified: chain.updated_at })
})
