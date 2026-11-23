import { describe, expect, it } from 'vitest'
import { type TraefikBundleSettings, traefikConfig, traefikJson, traefikNames, traefikRefs, traefikYaml } from '../src/traefik'

const pem = (body: string) => `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`
const one = pem('MIIAAA==')
const two = pem('MIIBBB==\nCCCC')

const bundle = (overrides: Partial<TraefikBundleSettings> = {}): TraefikBundleSettings => ({
  slug: 'internal',
  traefik_client_auth: true,
  traefik_client_auth_type: 'RequireAndVerifyClientCert',
  traefik_tls_option_name: null,
  traefik_servers_transport: true,
  traefik_servers_transport_name: null,
  ...overrides,
})

describe('traefik names', () => {
  it('defaults to the slug, with -mtls for the TLS option', () => {
    expect(traefikNames(bundle())).toEqual({ tls_option: 'internal-mtls', servers_transport: 'internal' })
    expect(traefikRefs(bundle())).toEqual({ tls_option: 'internal-mtls@http', servers_transport: 'internal@http' })
  })

  it('uses chosen names and leaves out the parts that are off', () => {
    const custom = bundle({ traefik_tls_option_name: 'clients', traefik_servers_transport_name: 'backends', traefik_servers_transport: false })
    expect(traefikRefs(custom)).toEqual({ tls_option: 'clients@http', servers_transport: null })
  })
})

describe('traefik YAML', () => {
  it('writes the TLS option and the servers transport with each certificate as a literal block', () => {
    expect(traefikYaml(traefikConfig(bundle(), [one, two]))).toBe(
      [
        'tls:',
        '  options:',
        '    internal-mtls:',
        '      minVersion: VersionTLS12',
        '      clientAuth:',
        '        caFiles:',
        '          - |',
        '            -----BEGIN CERTIFICATE-----',
        '            MIIAAA==',
        '            -----END CERTIFICATE-----',
        '          - |',
        '            -----BEGIN CERTIFICATE-----',
        '            MIIBBB==',
        '            CCCC',
        '            -----END CERTIFICATE-----',
        '        clientAuthType: RequireAndVerifyClientCert',
        'http:',
        '  serversTransports:',
        '    internal:',
        '      rootCAs:',
        '        - |',
        '          -----BEGIN CERTIFICATE-----',
        '          MIIAAA==',
        '          -----END CERTIFICATE-----',
        '        - |',
        '          -----BEGIN CERTIFICATE-----',
        '          MIIBBB==',
        '          CCCC',
        '          -----END CERTIFICATE-----',
        '',
      ].join('\n'),
    )
  })

  it('writes only the part that is on, with the chosen name and client auth type', () => {
    const yaml = traefikYaml(traefikConfig(bundle({ traefik_servers_transport: false, traefik_tls_option_name: 'edge', traefik_client_auth_type: 'VerifyClientCertIfGiven' }), [one]))
    expect(yaml).toContain('    edge:\n')
    expect(yaml).toContain('clientAuthType: VerifyClientCertIfGiven')
    expect(yaml).not.toContain('serversTransports')
    expect(yaml).not.toContain('http:')
  })

  it('quotes names that YAML would read as another type', () => {
    const yaml = traefikYaml(traefikConfig(bundle({ traefik_client_auth: false, traefik_servers_transport_name: 'true' }), [one]))
    expect(yaml).toContain('    "true":\n')
    expect(traefikYaml(traefikConfig(bundle({ traefik_client_auth: false, traefik_servers_transport_name: '123' }), [one]))).toContain('    "123":\n')
  })

  it('writes an empty document when nothing is on', () => {
    expect(traefikYaml({})).toBe('{}\n')
  })
})

describe('traefik JSON', () => {
  it('holds the same document', () => {
    const config = traefikConfig(bundle(), [one, two])
    expect(JSON.parse(traefikJson(config))).toEqual(config)
    expect(JSON.parse(traefikJson(config)).tls.options['internal-mtls'].clientAuth.caFiles).toEqual([one, two])
  })
})
