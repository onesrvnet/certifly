import { spawnSync } from 'node:child_process'
import { buildSshCertificate, formatAuthorizedKey, sshPublicKeyFromSpki, type SshCaSigner, type SshPublicKey } from '../src'

const probe = spawnSync('ssh-keygen', ['-V'], { encoding: 'utf8' })
// `ssh-keygen -V` without arguments prints usage; it only matters that the binary exists.
export const HAS_SSH_KEYGEN = !probe.error
export const SKIP_SSH_REASON = 'ssh-keygen is not installed, so the OpenSSH oracle tests are skipped'

export interface Run {
  status: number
  stdout: string
  stderr: string
}

export function run(command: string, args: string[], options: { cwd?: string; input?: string | Uint8Array; env?: Record<string, string> } = {}): Run {
  const result = spawnSync(command, args, { cwd: options.cwd, input: options.input, encoding: 'utf8', env: { ...process.env, ...options.env } })
  return { status: result.status ?? -1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

export function runOk(command: string, args: string[], options: { cwd?: string; input?: string | Uint8Array; env?: Record<string, string> } = {}): string {
  const result = run(command, args, options)
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
  return result.stdout + result.stderr
}

export type CaKind = 'ed25519' | 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-4096'

/** A CA key made with WebCrypto directly, for tests of the certificate encoder only. */
export async function testCa(kind: CaKind): Promise<{ signer: SshCaSigner; key: SshPublicKey; line: string }> {
  let pair: CryptoKeyPair
  let params: Algorithm | EcdsaParams
  let hash: string | undefined
  if (kind === 'ed25519') {
    pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    params = { name: 'Ed25519' }
  } else if (kind === 'rsa-4096') {
    pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512' }, true, ['sign', 'verify'])
    params = { name: 'RSASSA-PKCS1-v1_5' }
    hash = 'SHA-512'
  } else {
    const p384 = kind === 'ecdsa-p384'
    pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: p384 ? 'P-384' : 'P-256' }, true, ['sign', 'verify'])
    params = { name: 'ECDSA', hash: p384 ? 'SHA-384' : 'SHA-256' } as EcdsaParams
    hash = p384 ? 'SHA-384' : 'SHA-256'
  }
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
  const key = await sshPublicKeyFromSpki(spki, 'test-ca')
  const signer: SshCaSigner = {
    key_algorithm: kind,
    hash,
    sign: async (data) => new Uint8Array(await crypto.subtle.sign(params, pair.privateKey, data as BufferSource)),
  }
  return { signer, key, line: formatAuthorizedKey(key) }
}

export { buildSshCertificate }
