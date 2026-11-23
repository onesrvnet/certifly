import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalKeyProvider, loadKeyvaultConfig, type KeyAlgorithm } from '@certifly/keyvault'

// A disposable test master key; never a real one.
const TEST_KEK = '5e'.repeat(32)

let provider: Promise<LocalKeyProvider> | undefined

export function keyvault(): Promise<LocalKeyProvider> {
  provider ??= loadKeyvaultConfig({ master_key: TEST_KEK, session_secret: 'test-session-secret-0123456789abcdef' }).then((c) => new LocalKeyProvider(c))
  return provider
}

let counter = 0

/** A CA key held by the keyvault, with the signer that pki functions take. */
export async function caKey(algorithm: KeyAlgorithm) {
  const kv = await keyvault()
  const binding = `ca_key:test:${++counter}`
  const generated = await kv.generate(algorithm, binding)
  return { ...generated, binding, signer: kv.signer(generated.record, binding, algorithm) }
}

export const DAY = 24 * 60 * 60 * 1000

export function daysFromNow(days: number): Date {
  return new Date(Date.now() + days * DAY)
}

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' })
export const OPENSSL_VERSION = probe.status === 0 ? probe.stdout.trim() : null
export const SKIP_OPENSSL_REASON = 'the openssl CLI is not installed, so the OpenSSL oracle tests are skipped'

export interface OpensslResult {
  status: number
  stdout: string
  stderr: string
}

export function openssl(args: string[], options: { cwd: string; input?: string }): OpensslResult {
  const result = spawnSync('openssl', args, { cwd: options.cwd, input: options.input, encoding: 'utf8' })
  return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr }
}

/** Runs openssl and fails the test with its output when it exits non-zero. */
export function opensslOk(args: string[], options: { cwd: string; input?: string }): string {
  const result = openssl(args, options)
  if (result.status !== 0) throw new Error(`openssl ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`)
  return result.stdout + result.stderr
}

export function tempDir(): { dir: string; write: (name: string, data: string | Uint8Array) => string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-pki-'))
  return {
    dir,
    write(name, data) {
      const path = join(dir, name)
      writeFileSync(path, data)
      return path
    },
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}

/** OpenSSL prints key identifiers as colon-separated uppercase hex. */
export function opensslKeyId(hex: string): string {
  return hex.toUpperCase().match(/../g)!.join(':')
}
