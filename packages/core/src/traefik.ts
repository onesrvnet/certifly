/**
 * Traefik dynamic configuration for a trust bundle, served to Traefik's HTTP provider.
 *
 * The provider takes the same document as Traefik's file provider, as YAML or JSON. Both
 * `tls.options.<name>.clientAuth.caFiles` and `http.serversTransports.<name>.rootCAs` hold
 * `FileOrContent` values in Traefik, so each entry may be the PEM text itself instead of a path.
 */

export const TRAEFIK_CLIENT_AUTH_TYPES = ['RequireAndVerifyClientCert', 'VerifyClientCertIfGiven'] as const
export type TraefikClientAuthType = (typeof TRAEFIK_CLIENT_AUTH_TYPES)[number]

/** Names of TLS options and servers transports as the admin may choose them. */
export const TRAEFIK_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/

/** The bundle columns that decide what the Traefik document holds. */
export interface TraefikBundleSettings {
  slug: string
  traefik_client_auth: boolean
  traefik_client_auth_type: string
  traefik_tls_option_name: string | null
  traefik_servers_transport: boolean
  traefik_servers_transport_name: string | null
}

export interface TraefikConfig {
  tls?: {
    options: Record<string, { minVersion: string; clientAuth: { caFiles: string[]; clientAuthType: string } }>
  }
  http?: {
    serversTransports: Record<string, { rootCAs: string[] }>
  }
}

/** The names the document uses: the admin's, or the defaults built from the slug. */
export function traefikNames(bundle: Pick<TraefikBundleSettings, 'slug' | 'traefik_tls_option_name' | 'traefik_servers_transport_name'>) {
  return {
    tls_option: bundle.traefik_tls_option_name ?? `${bundle.slug}-mtls`,
    servers_transport: bundle.traefik_servers_transport_name ?? bundle.slug,
  }
}

/** How other Traefik configuration refers to the things this document defines. */
export function traefikRefs(bundle: TraefikBundleSettings) {
  const names = traefikNames(bundle)
  return {
    tls_option: bundle.traefik_client_auth ? `${names.tls_option}@http` : null,
    servers_transport: bundle.traefik_servers_transport ? `${names.servers_transport}@http` : null,
  }
}

/** The document for a bundle, from the PEM text of each of its certificates. */
export function traefikConfig(bundle: TraefikBundleSettings, certificates: string[]): TraefikConfig {
  const names = traefikNames(bundle)
  const config: TraefikConfig = {}
  if (bundle.traefik_client_auth) {
    config.tls = {
      options: {
        [names.tls_option]: { minVersion: 'VersionTLS12', clientAuth: { caFiles: certificates, clientAuthType: bundle.traefik_client_auth_type } },
      },
    }
  }
  if (bundle.traefik_servers_transport) {
    config.http = { serversTransports: { [names.servers_transport]: { rootCAs: certificates } } }
  }
  return config
}

type YamlValue = string | string[] | { [key: string]: YamlValue }

const SAFE_SCALAR = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/

function scalar(value: string): string {
  // Words such as `true` or `null` would read back as another type.
  return SAFE_SCALAR.test(value) && !/^(true|false|null|yes|no|on|off|y|n|~)$/i.test(value) && !/^[0-9.-]+$/.test(value) ? value : JSON.stringify(value)
}

/** A string list item: PEM text (several lines) as a literal block, anything else on one line. */
function item(value: string, indent: string): string[] {
  if (!value.includes('\n')) return [`${indent}- ${scalar(value)}`]
  // Clip chomping keeps exactly one final newline, which is what a PEM block ends with.
  const body = value.replace(/\n+$/, '').split('\n')
  return [`${indent}- |`, ...body.map((line) => `${indent}  ${line}`)]
}

function lines(value: { [key: string]: YamlValue }, indent: string): string[] {
  const out: string[] = []
  for (const [key, child] of Object.entries(value)) {
    const name = scalar(key)
    if (Array.isArray(child)) {
      if (!child.length) out.push(`${indent}${name}: []`)
      else {
        out.push(`${indent}${name}:`)
        for (const entry of child) out.push(...item(entry, `${indent}  `))
      }
    } else if (typeof child === 'string') out.push(`${indent}${name}: ${scalar(child)}`)
    else out.push(`${indent}${name}:`, ...lines(child, `${indent}  `))
  }
  return out
}

/** The document as YAML. Only the fixed shape of `TraefikConfig` is supported. */
export function traefikYaml(config: TraefikConfig): string {
  const body = lines(config as { [key: string]: YamlValue }, '')
  return body.length ? `${body.join('\n')}\n` : '{}\n'
}

export function traefikJson(config: TraefikConfig): string {
  return `${JSON.stringify(config, null, 2)}\n`
}
