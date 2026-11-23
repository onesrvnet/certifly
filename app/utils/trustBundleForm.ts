import type { CertificateAuthority, TraefikClientAuthType, TrustBundleDetail, TrustBundleTraefikInput } from '~/types/api'

/** What a trust bundle holds, as the create and edit pages edit it. */
export interface TrustBundleFormState {
  name: string
  slug: string
  description: string
  ca_ids: string[]
  include_chain: boolean
  traefik_enabled: boolean
  traefik_client_auth: boolean
  traefik_client_auth_type: TraefikClientAuthType
  /** Empty means the default name. */
  traefik_tls_option_name: string
  traefik_servers_transport: boolean
  /** Empty means the default name. */
  traefik_servers_transport_name: string
  traefik_require_token: boolean
}

export type TraefikFormState = Omit<TrustBundleFormState, 'name' | 'slug' | 'description' | 'ca_ids' | 'include_chain'>

export const TRAEFIK_CLIENT_AUTH_TYPES: TraefikClientAuthType[] = ['RequireAndVerifyClientCert', 'VerifyClientCertIfGiven']

/** The Traefik part of a new bundle's form: off, with both parts ready for when it is turned on. */
export const emptyTraefikForm = (): TraefikFormState => ({
  traefik_enabled: false,
  traefik_client_auth: true,
  traefik_client_auth_type: 'RequireAndVerifyClientCert',
  traefik_tls_option_name: '',
  traefik_servers_transport: true,
  traefik_servers_transport_name: '',
  traefik_require_token: false,
})

/** The Traefik part of the form for an existing bundle. */
export const traefikFormOf = (bundle: TrustBundleDetail): TraefikFormState => ({
  traefik_enabled: bundle.traefik_enabled,
  traefik_client_auth: bundle.traefik_client_auth,
  traefik_client_auth_type: bundle.traefik_client_auth_type as TraefikClientAuthType,
  traefik_tls_option_name: bundle.traefik_tls_option_name ?? '',
  traefik_servers_transport: bundle.traefik_servers_transport,
  traefik_servers_transport_name: bundle.traefik_servers_transport_name ?? '',
  traefik_require_token: bundle.traefik_require_token,
})

/** The Traefik fields of a create or update call; a blank name goes as null, the default. */
export const traefikPayload = (form: TrustBundleFormState): Required<TrustBundleTraefikInput> => ({
  traefik_enabled: form.traefik_enabled,
  traefik_client_auth: form.traefik_client_auth,
  traefik_client_auth_type: form.traefik_client_auth_type,
  traefik_tls_option_name: form.traefik_tls_option_name.trim() || null,
  traefik_servers_transport: form.traefik_servers_transport,
  traefik_servers_transport_name: form.traefik_servers_transport_name.trim() || null,
  traefik_require_token: form.traefik_require_token,
})

/** The server's rule for TLS option and servers transport names, as an input `pattern`. */
export const TRAEFIK_NAME_INPUT_PATTERN = '[A-Za-z0-9][A-Za-z0-9_\\-]{0,62}'

/** Every CA: a single-tenant instance has a handful, so follow the cursor to the end. */
export async function loadAllCas(rpc: ReturnType<typeof useRpc>) {
  const all: CertificateAuthority[] = []
  let cursor: string | undefined
  do {
    const res = await rpc('certificate_authorities.list', { cursor, limit: 200 })
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  return all
}
