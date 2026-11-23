import { AuthenticationError } from '@certifly/core/errors'
import { publicTraefikConfig } from '@certifly/core/trust-bundles'
import { traefikJson, traefikYaml } from '@certifly/core/traefik'

/**
 * A trust bundle as Traefik configuration
 *
 * `GET /api/pki/bundle/<slug>/traefik.yml` (or `traefik.json`): dynamic configuration for
 * Traefik's HTTP provider. It holds a TLS option that verifies client certificates against the
 * bundle and/or a servers transport that trusts backends signed by it, with the certificates
 * inline. Answers 404 unless the bundle exists and has Traefik turned on. When the bundle asks for
 * a token, send it as `Authorization: Bearer tb_…` (401 without one, 403 for a token that is not
 * the bundle's). Never cached.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'pki', clientIp(event))
  const slug = caSlug(getRouterParam(event, 'slug'))
  const file = getRouterParam(event, 'file')
  const json = file === 'traefik.json'
  if (!slug || (!json && file !== 'traefik.yml')) throw notFound()

  const header = getRequestHeader(event, 'authorization')
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() || null : null
  const result = await publicTraefikConfig(useContext(), slug, token).catch((error) => {
    if (error instanceof AuthenticationError) setResponseHeader(event, 'www-authenticate', 'Bearer')
    throw toHttpError(error)
  })
  if (!result) throw notFound()
  setResponseHeaders(event, {
    'content-type': json ? 'application/json' : 'application/yaml',
    'cache-control': 'no-cache',
    vary: 'authorization',
  })
  return json ? traefikJson(result.config) : traefikYaml(result.config)
})
