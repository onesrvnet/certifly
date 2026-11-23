import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export const hasSshKeygen = !spawnSync('ssh-keygen', ['-?'], { encoding: 'utf8' }).error

export function run(command: string, args: string[], options: { cwd?: string; env?: Record<string, string> } = {}) {
  const result = spawnSync(command, args, { cwd: options.cwd, encoding: 'utf8', env: { ...process.env, ...options.env } })
  return { status: result.status ?? -1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

/** A scratch directory for ssh-keygen keys, removed with `cleanup`. */
export function sshWorkdir() {
  const dir = mkdtempSync(join(tmpdir(), 'certifly-ssh-api-'))
  return {
    dir,
    /** A key pair made by ssh-keygen; `pub` is the authorized_keys line without comment. */
    keygen(name: string, args: string[] = ['-t', 'ed25519']) {
      const path = join(dir, name)
      const result = run('ssh-keygen', [...args, '-q', '-N', '', '-C', `${name}@test`, '-f', path])
      if (result.status !== 0) throw new Error(`ssh-keygen failed: ${result.stderr}`)
      return { path, pub: readFileSync(`${path}.pub`, 'utf8').trim() }
    },
    write(name: string, data: string | Uint8Array) {
      const path = join(dir, name)
      writeFileSync(path, data)
      return path
    },
    /** `ssh-keygen -L` for a certificate line. */
    describe(line: string) {
      const path = join(dir, `describe-${Math.random().toString(36).slice(2)}.pub`)
      writeFileSync(path, `${line}\n`)
      const result = run('ssh-keygen', ['-L', '-f', path], { env: { TZ: 'UTC' } })
      return { path, ...result }
    },
    /** An armored SSHSIG over exactly these bytes, made with the key at `keyPath`. */
    sign(keyPath: string, message: string, namespace = 'certifly-host@certifly') {
      const file = join(dir, `msg-${Math.random().toString(36).slice(2)}`)
      writeFileSync(file, message)
      const result = run('ssh-keygen', ['-Y', 'sign', '-n', namespace, '-f', keyPath, file])
      if (result.status !== 0) throw new Error(`ssh-keygen -Y sign failed: ${result.stderr}`)
      return readFileSync(`${file}.sig`, 'utf8')
    },
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}
