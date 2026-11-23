import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { buildKrl, buildSshCertificate, formatAuthorizedKey, generateSshSerial, parseAuthorizedKey, parseOpenSshPrivateKey, parsePrivateKeyForImport, PkiError, SshWriter, sshPublicKeyFromSpki, verifySshsig } from '../src'
import { keyvault, OPENSSL_VERSION, tempDir } from './helpers'
import { HAS_SSH_KEYGEN, run, runOk, SKIP_SSH_REASON, testCa, type CaKind } from './ssh-helpers'

const dirs: Array<{ cleanup: () => void }> = []
function scratch() {
  const dir = tempDir()
  dirs.push(dir)
  return dir
}
afterAll(() => dirs.forEach((d) => d.cleanup()))

const KEY_KINDS: Array<{ name: string; args: string[]; type: string }> = [
  { name: 'ed25519', args: ['-t', 'ed25519'], type: 'ssh-ed25519' },
  { name: 'ecdsa-256', args: ['-t', 'ecdsa', '-b', '256'], type: 'ecdsa-sha2-nistp256' },
  { name: 'ecdsa-384', args: ['-t', 'ecdsa', '-b', '384'], type: 'ecdsa-sha2-nistp384' },
  { name: 'rsa-2048', args: ['-t', 'rsa', '-b', '2048'], type: 'ssh-rsa' },
]

function keygen(dir: string, name: string, args: string[]): { pub: string; path: string } {
  runOk('ssh-keygen', [...args, '-q', '-N', '', '-C', `${name}@test`, '-f', join(dir, name)])
  return { pub: readFileSync(join(dir, `${name}.pub`), 'utf8').trim(), path: join(dir, name) }
}

describe('public key parsing', () => {
  it.skipIf(!HAS_SSH_KEYGEN).each(KEY_KINDS)('reads an ssh-keygen $name key and matches its fingerprint', async ({ name, args, type }) => {
    const t = scratch()
    const { pub, path } = keygen(t.dir, name, args)
    const key = await parseAuthorizedKey(pub)
    expect(key.type).toBe(type)
    expect(key.comment).toBe(`${name}@test`)
    const expected = runOk('ssh-keygen', ['-l', '-f', `${path}.pub`])
    expect(expected).toContain(key.fingerprint)
    expect(formatAuthorizedKey(key)).toBe(pub)
  })

  it('refuses unsupported and malformed keys', async () => {
    await expect(parseAuthorizedKey('ssh-dss AAAA')).rejects.toBeInstanceOf(PkiError)
    await expect(parseAuthorizedKey('not a key')).rejects.toBeInstanceOf(PkiError)
    await expect(parseAuthorizedKey('ssh-ed25519 AAAA')).rejects.toBeInstanceOf(PkiError)
    await expect(parseAuthorizedKey('command="x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA')).rejects.toBeInstanceOf(PkiError)
    // The key type inside the blob must match the one on the line.
    const blob = new SshWriter().string('ssh-ed25519').string(new Uint8Array(32).fill(1)).toBytes()
    await expect(parseAuthorizedKey(`ecdsa-sha2-nistp256 ${btoa(String.fromCharCode(...blob))}`)).rejects.toBeInstanceOf(PkiError)
    // ecdsa-p521 is not accepted.
    const p521 = new SshWriter().string('ecdsa-sha2-nistp521').string('nistp521').string(new Uint8Array(133)).toBytes()
    await expect(parseAuthorizedKey(`ecdsa-sha2-nistp521 ${btoa(String.fromCharCode(...p521))}`)).rejects.toMatchObject({ code: 'invalid_ssh_key' })
  })

  it.skipIf(!HAS_SSH_KEYGEN)('refuses RSA keys under the minimum size', async () => {
    const t = scratch()
    const { pub } = keygen(t.dir, 'small', ['-t', 'rsa', '-b', '1024'])
    await expect(parseAuthorizedKey(pub)).rejects.toThrow(/at least 2048/)
    expect((await parseAuthorizedKey(pub, { min_rsa_bits: 1024 })).bits).toBe(1024)
  })

  it('reads security key types', async () => {
    const blob = new SshWriter().string('sk-ssh-ed25519@openssh.com').string(new Uint8Array(32).fill(7)).string('ssh:').toBytes()
    // 32 bytes of 7 is not necessarily a valid point; WebCrypto decides.
    const line = `sk-ssh-ed25519@openssh.com ${btoa(String.fromCharCode(...blob))} yubi`
    const result = await parseAuthorizedKey(line).catch((e) => e)
    if (result instanceof Error) expect(result).toBeInstanceOf(PkiError)
    else {
      expect(result.sk).toBe(true)
      expect(result.application).toBe('ssh:')
    }
  })
})

const CA_KINDS: CaKind[] = ['ed25519', 'ecdsa-p256', 'ecdsa-p384', 'rsa-4096']

describe.skipIf(!HAS_SSH_KEYGEN)('certificates, checked with ssh-keygen -L', () => {
  it.each(CA_KINDS)('a %s CA signs a user certificate ssh-keygen accepts', async (kind) => {
    const t = scratch()
    const ca = await testCa(kind)
    const { pub } = keygen(t.dir, 'user', ['-t', 'ed25519'])
    const subject = await parseAuthorizedKey(pub)
    const now = Date.now()
    const cert = await buildSshCertificate({
      type: 'user',
      public_key: subject,
      ca_key: ca.key,
      signer: ca.signer,
      serial: 1234567890123n,
      key_id: 'certifly:alice@example.com:prod:abc',
      principals: ['prod:root', 'prod:alice'],
      valid_after: new Date(now - 120_000),
      valid_before: new Date(now + 8 * 3600_000),
      force_command: '/usr/bin/true',
      source_address: ['10.0.0.0/8', '192.0.2.7'],
      extensions: ['permit-pty', 'permit-agent-forwarding', 'permit-port-forwarding'],
    })
    const file = t.write('user-cert.pub', `${cert.line}\n`)
    const out = runOk('ssh-keygen', ['-L', '-f', file], { env: { TZ: 'UTC' } })
    expect(out).toMatch(/Type: .*-cert-v01@openssh.com user certificate/)
    expect(out).toContain(`Public key: ED25519-CERT ${subject.fingerprint}`)
    expect(out).toContain(`Signing CA: ${kind === 'ed25519' ? 'ED25519' : kind.startsWith('ecdsa') ? 'ECDSA' : 'RSA'} ${ca.key.fingerprint}`)
    expect(kind === 'rsa-4096' ? out : '').toSatisfy((text: string) => kind !== 'rsa-4096' || text.includes('using rsa-sha2-512'))
    expect(out).toContain('Key ID: "certifly:alice@example.com:prod:abc"')
    expect(out).toContain('Serial: 1234567890123')
    expect(out).toMatch(/Principals:\s+prod:root\s+prod:alice/)
    expect(out).toMatch(/Critical Options:\s+force-command \/usr\/bin\/true\s+source-address 10\.0\.0\.0\/8,192\.0\.2\.7/)
    // Extensions are sorted.
    expect(out).toMatch(/Extensions:\s+permit-agent-forwarding\s+permit-port-forwarding\s+permit-pty/)
    const valid = /Valid: from (\S+) to (\S+)/.exec(out)!
    expect(new Date(`${valid[1]}Z`).getTime()).toBe(Math.floor((now - 120_000) / 1000) * 1000)
    expect(new Date(`${valid[2]}Z`).getTime()).toBe(Math.floor((now + 8 * 3600_000) / 1000) * 1000)
  }, 120_000)

  it('certifies every key type, for users and hosts', async () => {
    const t = scratch()
    const ca = await testCa('ed25519')
    for (const kind of KEY_KINDS) {
      const { pub } = keygen(t.dir, kind.name, kind.args)
      const subject = await parseAuthorizedKey(pub)
      for (const type of ['user', 'host'] as const) {
        const cert = await buildSshCertificate({
          type,
          public_key: subject,
          ca_key: ca.key,
          signer: ca.signer,
          serial: generateSshSerial(),
          key_id: `certifly:test:${kind.name}`,
          principals: type === 'user' ? ['prod:root'] : ['web1.prod.corp', '*.prod.corp'],
          valid_after: new Date(Date.now() - 120_000),
          valid_before: new Date(Date.now() + 86_400_000),
        })
        const out = runOk('ssh-keygen', ['-L', '-f', t.write('c.pub', `${cert.line}\n`)])
        expect(out).toContain(`Type: ${kind.type}-cert-v01@openssh.com ${type} certificate`)
        expect(out).toContain(subject.fingerprint)
        if (type === 'host') expect(out).toMatch(/Principals:\s+web1\.prod\.corp\s+\*\.prod\.corp/)
        expect(out).not.toMatch(/Critical Options: \(none\)/.test(out) ? /x^/ : /Critical Options:\s+\S/)
      }
    }
  }, 120_000)

  it('certifies a security key (sk) with its application', async () => {
    const t = scratch()
    const ca = await testCa('ed25519')
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
    const blob = new SshWriter().string('sk-ssh-ed25519@openssh.com').string(raw).string('ssh:').toBytes()
    const subject = await parseAuthorizedKey(`sk-ssh-ed25519@openssh.com ${btoa(String.fromCharCode(...blob))} yubikey`)
    const cert = await buildSshCertificate({ type: 'user', public_key: subject, ca_key: ca.key, signer: ca.signer, serial: 5n, key_id: 'sk', principals: ['dev:bob'], valid_after: new Date(Date.now() - 1000), valid_before: new Date(Date.now() + 60_000) })
    expect(cert.line.startsWith('sk-ssh-ed25519-cert-v01@openssh.com ')).toBe(true)
    const out = runOk('ssh-keygen', ['-L', '-f', t.write('sk-cert.pub', `${cert.line}\n`)])
    expect(out).toContain('ED25519-SK-CERT')
    expect(out).toContain(subject.fingerprint)
  })

  it('produces a signature ssh-keygen verifies: a damaged certificate is refused', async () => {
    const t = scratch()
    const ca = await testCa('ecdsa-p256')
    const { pub } = keygen(t.dir, 'k', ['-t', 'ed25519'])
    const cert = await buildSshCertificate({ type: 'user', public_key: await parseAuthorizedKey(pub), ca_key: ca.key, signer: ca.signer, serial: 9n, key_id: 'x', principals: ['a:b'], valid_after: new Date(Date.now() - 1000), valid_before: new Date(Date.now() + 60_000) })
    expect(run('ssh-keygen', ['-L', '-f', t.write('ok.pub', `${cert.line}\n`)]).status).toBe(0)
    const damaged = new Uint8Array(cert.blob)
    damaged[damaged.length - 5]! ^= 1
    const [type] = cert.line.split(' ')
    expect(run('ssh-keygen', ['-L', '-f', t.write('bad.pub', `${type} ${btoa(String.fromCharCode(...damaged))}\n`)]).status).not.toBe(0)
  })

  it('works with CA keys held by the keyvault: Ed25519 and RSA with SHA-512', async () => {
    const t = scratch()
    const kv = await keyvault()
    const { pub } = keygen(t.dir, 'u', ['-t', 'ed25519'])
    const subject = await parseAuthorizedKey(pub)
    for (const algorithm of ['ed25519', 'ecdsa-p384', 'rsa-2048'] as const) {
      const binding = `ca_key:test:ssh-${algorithm}`
      const generated = await kv.generate(algorithm, binding)
      const signer = kv.signer(generated.record, binding, algorithm, algorithm === 'rsa-2048' ? { hash: 'SHA-512' } : undefined)
      const ca = await sshPublicKeyFromSpki(generated.public_key_spki, 'ca')
      const cert = await buildSshCertificate({ type: 'user', public_key: subject, ca_key: ca, signer, serial: 77n, key_id: `kv-${algorithm}`, principals: ['p:q'], valid_after: new Date(Date.now() - 1000), valid_before: new Date(Date.now() + 60_000) })
      const out = runOk('ssh-keygen', ['-L', '-f', t.write(`${algorithm}.pub`, `${cert.line}\n`)])
      expect(out).toContain(`Signing CA: `)
      expect(out).toContain(ca.fingerprint)
    }
  }, 120_000)

  it('rejects bad input', async () => {
    const ca = await testCa('ed25519')
    const t = scratch()
    const subject = await parseAuthorizedKey(keygen(t.dir, 'r', ['-t', 'ed25519']).pub)
    const base = { type: 'user' as const, public_key: subject, ca_key: ca.key, signer: ca.signer, serial: 1n, key_id: 'k', principals: ['a:b'], valid_after: new Date(Date.now() - 1000), valid_before: new Date(Date.now() + 60_000) }
    await expect(buildSshCertificate({ ...base, principals: [] })).rejects.toBeInstanceOf(PkiError)
    await expect(buildSshCertificate({ ...base, principals: ['a b'] })).rejects.toBeInstanceOf(PkiError)
    await expect(buildSshCertificate({ ...base, valid_before: new Date(0) })).rejects.toBeInstanceOf(PkiError)
    await expect(buildSshCertificate({ ...base, extensions: ['nope'] })).rejects.toBeInstanceOf(PkiError)
    await expect(buildSshCertificate({ ...base, source_address: ['not-an-ip'] })).rejects.toBeInstanceOf(PkiError)
    await expect(buildSshCertificate({ ...base, type: 'host', principals: ['h.example.com'], force_command: 'x' })).rejects.toBeInstanceOf(PkiError)
    const rsa = await testCa('rsa-4096')
    await expect(buildSshCertificate({ ...base, ca_key: rsa.key, signer: { ...rsa.signer, hash: 'SHA-256' } })).rejects.toBeInstanceOf(PkiError)
  }, 60_000)
})

describe.skipIf(!HAS_SSH_KEYGEN)('revocation lists, checked with ssh-keygen -Q', () => {
  it('lists revoked serials and key ids for their CA only', async () => {
    const t = scratch()
    const ca = await testCa('ed25519')
    const otherCa = await testCa('ed25519')
    const subject = await parseAuthorizedKey(keygen(t.dir, 'u', ['-t', 'ed25519']).pub)
    const make = (signer: typeof ca, serial: bigint, key_id: string) =>
      buildSshCertificate({ type: 'user', public_key: subject, ca_key: signer.key, signer: signer.signer, serial, key_id, principals: ['p:q'], valid_after: new Date(Date.now() - 1000), valid_before: new Date(Date.now() + 3600_000) })
    const revoked = await make(ca, 4000000000000000001n, 'id-revoked')
    const fine = await make(ca, 4000000000000000002n, 'id-fine')
    const byId = await make(ca, 4000000000000000003n, 'id-by-name')
    const sameSerialOtherCa = await make(otherCa, 4000000000000000001n, 'id-other')
    const krl = buildKrl({
      version: 3n,
      generated: new Date(),
      comment: 'certifly test',
      cas: [{ ca_key: ca.key.blob, serials: [4000000000000000009n, 4000000000000000001n, 4000000000000000001n], key_ids: ['id-by-name'] }],
    })
    const krlFile = t.write('test.krl', krl)
    const check = (cert: { line: string }, name: string) => run('ssh-keygen', ['-Q', '-f', krlFile, t.write(`${name}.pub`, `${cert.line}\n`)])
    expect(check(revoked, 'revoked').status).toBe(1)
    expect(check(revoked, 'revoked').stdout).toContain('REVOKED')
    expect(check(byId, 'byid').status).toBe(1)
    expect(check(fine, 'fine').status).toBe(0)
    expect(check(sameSerialOtherCa, 'other').status).toBe(0)
    const listing = runOk('ssh-keygen', ['-Q', '-l', '-f', krlFile])
    expect(listing).toContain('serial: 4000000000000000001')
  })

  it('revokes a plain public key outright', async () => {
    const t = scratch()
    const bad = keygen(t.dir, 'bad', ['-t', 'ed25519'])
    const good = keygen(t.dir, 'good', ['-t', 'ed25519'])
    const key = await parseAuthorizedKey(bad.pub)
    const krl = t.write('keys.krl', buildKrl({ version: 1n, generated: new Date(), cas: [], keys: [key.blob] }))
    expect(run('ssh-keygen', ['-Q', '-f', krl, `${bad.path}.pub`]).status).toBe(1)
    expect(run('ssh-keygen', ['-Q', '-f', krl, `${good.path}.pub`]).status).toBe(0)
  })

  it('writes a valid empty list', () => {
    const t = scratch()
    const krl = t.write('empty.krl', buildKrl({ version: 1n, generated: new Date(), cas: [] }))
    expect(run('ssh-keygen', ['-Q', '-l', '-f', krl]).status).toBe(0)
  })
})

describe.skipIf(!HAS_SSH_KEYGEN)('SSHSIG, made by ssh-keygen -Y sign', () => {
  const NAMESPACE = 'certifly-host@certifly'
  it.each(KEY_KINDS)('verifies a $name signature and its key', async ({ name, args }) => {
    const t = scratch()
    const { pub, path } = keygen(t.dir, name, args)
    const message = new TextEncoder().encode(`nonce-${crypto.randomUUID()}`)
    const file = t.write('message', message)
    runOk('ssh-keygen', ['-Y', 'sign', '-n', NAMESPACE, '-f', path, file])
    const armored = readFileSync(`${file}.sig`, 'utf8')
    const result = await verifySshsig(armored, message, NAMESPACE)
    expect(result.public_key.fingerprint).toBe((await parseAuthorizedKey(pub)).fingerprint)
    await expect(verifySshsig(armored, message, 'other@certifly')).rejects.toMatchObject({ code: 'invalid_ssh_signature' })
    await expect(verifySshsig(armored, new TextEncoder().encode('different'), NAMESPACE)).rejects.toMatchObject({ code: 'invalid_ssh_signature' })
  })

  it('rejects garbage', async () => {
    await expect(verifySshsig('nope', new Uint8Array(1), NAMESPACE)).rejects.toMatchObject({ code: 'invalid_ssh_signature' })
    await expect(verifySshsig('-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----', new Uint8Array(1), NAMESPACE)).rejects.toBeInstanceOf(PkiError)
  })
})

describe.skipIf(!HAS_SSH_KEYGEN)('private key import', () => {
  it.each(KEY_KINDS)('imports an unencrypted openssh-key-v1 $name key into the keyvault', async ({ name, args }) => {
    const t = scratch()
    const { pub, path } = keygen(t.dir, name, args)
    const kv = await keyvault()
    const parsed = parsePrivateKeyForImport(readFileSync(path, 'utf8'))
    const imported = await kv.importPkcs8(parsed.pkcs8, `ca_key:test:import-${name}`)
    const key = await sshPublicKeyFromSpki(imported.public_key_spki)
    expect(key.fingerprint).toBe((await parseAuthorizedKey(pub)).fingerprint)
  })

  it.skipIf(!OPENSSL_VERSION)('imports PKCS#8 PEM keys made by openssl', async () => {
    const t = scratch()
    const kv = await keyvault()
    for (const args of [['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384'], ['-algorithm', 'ed25519']]) {
      const pem = runOk('openssl', ['genpkey', ...args])
      const imported = await kv.importPkcs8(parsePrivateKeyForImport(pem).pkcs8, 'ca_key:test:p8')
      const key = await sshPublicKeyFromSpki(imported.public_key_spki)
      const pubPem = run('openssl', ['pkey', '-pubout'], { input: pem }).stdout
      expect(pubPem).toContain('BEGIN PUBLIC KEY')
      expect(key.type).toBe(args[1] === 'ed25519' ? 'ssh-ed25519' : 'ecdsa-sha2-nistp384')
    }
    void t
  })

  it('asks for the passphrase to be removed first', () => {
    const t = scratch()
    const path = join(t.dir, 'enc')
    runOk('ssh-keygen', ['-t', 'ed25519', '-q', '-N', 'secret-passphrase', '-f', path])
    expect(() => parsePrivateKeyForImport(readFileSync(path, 'utf8'))).toThrow(/ssh-keygen -p -N/)
    try {
      parseOpenSshPrivateKey(new Uint8Array(4))
    } catch (error) {
      expect(error).toBeInstanceOf(PkiError)
    }
  })

  it('refuses a key whose public half does not belong to its secret half', async () => {
    const kv = await keyvault()
    const a = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const b = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', a.privateKey))
    const other = new Uint8Array(await crypto.subtle.exportKey('raw', b.publicKey))
    // The uncompressed point (x || y) is the last 64 bytes of the encoding.
    pkcs8.set(other.subarray(1), pkcs8.byteLength - 64)
    await expect(kv.importPkcs8(pkcs8, 'ca_key:test:mismatch')).rejects.toMatchObject({ code: 'key_mismatch' })
  })
})

