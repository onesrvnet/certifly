import { type ChildProcess, spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { userInfo } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { buildKrl, buildSshCertificate, parseAuthorizedKey, sshPublicKeyFromSpki, formatAuthorizedKey } from '../src'
import { keyvault, tempDir } from './helpers'
import { HAS_SSH_KEYGEN, run, runOk } from './ssh-helpers'

const SSHD = '/usr/sbin/sshd'
const runnable = HAS_SSH_KEYGEN && existsSync(SSHD)

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number }
      server.close(() => resolve(port))
    })
    server.on('error', reject)
  })
}

async function waitForPort(port: number, child: ChildProcess): Promise<void> {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('sshd exited early')
    const ok = await new Promise<boolean>((resolve) => {
      const socket = createServer()
      socket.once('error', () => resolve(true)) // address in use: sshd is listening
      socket.listen(port, '127.0.0.1', () => socket.close(() => resolve(false)))
    })
    if (ok) return
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('sshd did not start')
}

const dir = tempDir()
let sshd: ChildProcess | undefined
afterAll(() => {
  sshd?.kill()
  dir.cleanup()
})

describe.skipIf(!runnable)('a real sshd accepts certifly certificates and honours the KRL', () => {
  it('logs in with a user certificate, checks the host certificate, and refuses after revocation', async () => {
    const me = userInfo().username
    const kv = await keyvault()
    const binding = 'ca_key:test:sshd'
    const generated = await kv.generate('ed25519', binding)
    const signer = kv.signer(generated.record, binding, 'ed25519')
    const ca = await sshPublicKeyFromSpki(generated.public_key_spki, 'test-ca')
    const caFile = dir.write('ca.pub', `${formatAuthorizedKey(ca)}\n`)

    runOk('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(dir.dir, 'host')])
    runOk('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(dir.dir, 'user')])
    const validity = { valid_after: new Date(Date.now() - 120_000), valid_before: new Date(Date.now() + 3600_000) }
    const hostCert = await buildSshCertificate({
      type: 'host',
      public_key: await parseAuthorizedKey(readFileSync(join(dir.dir, 'host.pub'), 'utf8')),
      ca_key: ca,
      signer,
      serial: 41n,
      key_id: 'certifly:host:127.0.0.1:test',
      principals: ['127.0.0.1', 'localhost'],
      ...validity,
    })
    const makeUserCert = (serial: bigint, principals: string[]) =>
      buildSshCertificate({ type: 'user', public_key: userKey, ca_key: ca, signer, serial, key_id: `certifly:test:${serial}`, principals, extensions: ['permit-pty'], ...validity })
    const userKey = await parseAuthorizedKey(readFileSync(join(dir.dir, 'user.pub'), 'utf8'))
    const good = await makeUserCert(1001n, ['prod:' + me])
    const wrongPrincipal = await makeUserCert(1002n, ['prod:someone-else'])
    const goodFile = dir.write('good-cert.pub', `${good.line}\n`)
    const wrongFile = dir.write('wrong-cert.pub', `${wrongPrincipal.line}\n`)
    dir.write('host-cert.pub', `${hostCert.line}\n`)
    dir.write('principals', `prod:${me}\n`)
    const krlFile = join(dir.dir, 'revoked.krl')
    dir.write('revoked.krl', buildKrl({ version: 1n, generated: new Date(), cas: [] }))

    const port = await freePort()
    dir.write(
      'sshd_config',
      [
        `Port ${port}`,
        'ListenAddress 127.0.0.1',
        `HostKey ${join(dir.dir, 'host')}`,
        `HostCertificate ${join(dir.dir, 'host-cert.pub')}`,
        `PidFile ${join(dir.dir, 'sshd.pid')}`,
        `TrustedUserCAKeys ${caFile}`,
        `AuthorizedPrincipalsFile ${join(dir.dir, 'principals')}`,
        `RevokedKeys ${krlFile}`,
        'AuthorizedKeysFile none',
        'PasswordAuthentication no',
        'KbdInteractiveAuthentication no',
        'UsePAM no',
        'StrictModes no',
        'LogLevel DEBUG1',
      ].join('\n') + '\n',
    )
    sshd = spawn(SSHD, ['-D', '-e', '-f', join(dir.dir, 'sshd_config')], { stdio: 'ignore' })
    await waitForPort(port, sshd)

    dir.write('known_hosts', `@cert-authority 127.0.0.1,localhost ${formatAuthorizedKey(ca)}\n`)
    const login = (cert: string) =>
      run(
        'ssh',
        [
          '-p', String(port),
          '-o', `CertificateFile=${cert}`,
          '-i', join(dir.dir, 'user'),
          '-o', 'IdentitiesOnly=yes',
          '-o', 'BatchMode=yes',
          '-o', 'StrictHostKeyChecking=yes',
          '-o', `UserKnownHostsFile=${join(dir.dir, 'known_hosts')}`,
          '-o', 'IdentityAgent=none',
          `${me}@127.0.0.1`,
          'true',
        ],
        { cwd: dir.dir },
      )

    // The host presents a certificate; the client trusts it only through the CA.
    const ok = login(goodFile)
    expect(ok.stderr, ok.stderr).not.toMatch(/Permission denied|REMOTE HOST IDENTIFICATION/)
    expect(ok.status).toBe(0)
    // A certificate without a principal the host maps to this user is refused.
    expect(login(wrongFile).status).not.toBe(0)

    // Revoking the serial turns the same certificate away.
    dir.write('revoked.krl', buildKrl({ version: 2n, generated: new Date(), cas: [{ ca_key: ca.blob, serials: [1001n] }] }))
    expect(run('ssh-keygen', ['-Q', '-f', krlFile, goodFile]).status).toBe(1)
    expect(login(goodFile).status).not.toBe(0)
  }, 60_000)
})
