import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fetch } from '@nuxt/test-utils/e2e'
import { Client, setupAdmin } from '../helpers'

export const hasOpenssl = spawnSync('openssl', ['version']).status === 0

const none = { dns: [], ip: [], email: [] }

export async function ok(client: Client, method: string, body: object) {
  const res = await client.rpc(method, body)
  if (res.status !== 200) throw new Error(`${method} failed: ${JSON.stringify(res.body)}`)
  return res.body.data
}

/** A scratch directory with an OpenSSL runner that fails the test on errors. */
export function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-est-test-'))
  const run = (args: string[], input?: string | Buffer) => {
    const result = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8', input })
    if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
    return result.stdout
  }
  return {
    dir,
    run,
    write: (name: string, data: string | Uint8Array) => writeFileSync(join(dir, name), data),
    read: (name: string) => readFileSync(join(dir, name), 'utf8'),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}

/** A key and a PKCS#10 request for `name` as an EST client sends it: base64 of the DER, in lines. */
export function makeRequest(dir: ReturnType<typeof scratch>, name: string, options: { subject?: string; sans?: string } = {}) {
  const base = name.replace(/\W/g, '_')
  dir.run([
    'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', `${base}.key`, '-out', `${base}.csr`,
    '-subj', options.subject ?? `/CN=${name}`, '-addext', `subjectAltName=${options.sans ?? `DNS:${name}`}`,
  ])
  const der = spawnSyncBuffer(dir.dir, ['req', '-in', `${base}.csr`, '-outform', 'DER'])
  return der.toString('base64').replace(/.{1,64}/g, '$&\n')
}

function spawnSyncBuffer(cwd: string, args: string[]) {
  const result = spawnSync('openssl', args, { cwd })
  if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed: ${result.stderr}`)
  return result.stdout
}

/** The PEM certificates in a base64 PKCS#7 answer, read by OpenSSL. */
export function certificatesOf(dir: ReturnType<typeof scratch>, base64: string): string[] {
  const pem = dir.run(['pkcs7', '-inform', 'DER', '-print_certs'], Buffer.from(base64.replace(/\s+/g, ''), 'base64'))
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\n/g) ?? []
}

/** The certificate as a Traefik `passTLSClientCert` header carries it: the PEM body without delimiters or line breaks. */
export const traefikHeader = (pem: string) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s+/g, '')

export const basic = (username: string, password: string) => `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`

export function est(slug: string, action: string, options: { auth?: string; body?: string; headers?: Record<string, string>; method?: 'GET' | 'POST' } = {}) {
  const method = options.method ?? (action === 'cacerts' || action === 'csrattrs' ? 'GET' : 'POST')
  return fetch(`/.well-known/est/${slug}/${action}`, {
    method,
    headers: { ...(options.body !== undefined ? { 'content-type': 'application/pkcs10', 'content-transfer-encoding': 'base64' } : {}), ...(options.auth ? { authorization: options.auth } : {}), ...options.headers },
    body: options.body,
  })
}

/**
 * A root, an issuing CA below it limited to example.test, a default tag, and two EST templates
 * (`devices` tagged, `printers`) plus one without EST.
 */
export async function estWorld() {
  const admin = await setupAdmin()
  const adminKey = (await admin.rpc('api_keys.create', { name: 'ci' })).body.data.secret as string
  const root = await ok(admin, 'certificate_authorities.create', { signing: 'self_signed', name: 'Root', slug: 'root', subject: [{ type: 'CN', value: 'Est Root' }], validity_days: 3650, path_length: 1 })
  const issuing = await ok(admin, 'certificate_authorities.create', {
    signing: 'internal',
    parent_ca_id: root.id,
    name: 'Issuing',
    slug: 'issuing',
    subject: [{ type: 'CN', value: 'Est Issuing CA' }],
    validity_days: 365,
    path_length: 0,
    name_constraints: { permitted: { ...none, dns: ['example.test'] }, excluded: none },
  })
  const tag = await ok(admin, 'tags.create', { name: 'Devices', color: 'green' })
  const template = (slug: string, extra: object = {}) =>
    ok(admin, 'templates.create', { preset: 'webserver_tls', name: slug, slug, ca_id: issuing.id, allowed_dns: ['**.example.test'], allow_est: true, default_ttl_seconds: 7 * 86400, ...extra })
  const devices = await template('devices', { tag_ids: [tag.id] })
  const printers = await template('printers')
  const plain = await template('plain', { allow_est: false })
  return { admin, adminKey, root, issuing, tag, devices, printers, plain }
}
