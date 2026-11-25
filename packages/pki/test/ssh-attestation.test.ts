import { describe, expect, it } from 'vitest'
import { parseAuthorizedKey, SshWriter, verifyFidoAttestation, type SshPublicKey } from '../src'
import * as x509 from '../src/x509'

// A throwaway attestation authority stands in for Yubico: the bundled roots are the real ones, so
// these tests pass extra roots. A real YubiKey attestation file has not been available to test with.

const AAGUID = new Uint8Array(16).map((_, i) => i + 1)
const CHALLENGE: Uint8Array<ArrayBuffer> = new Uint8Array(32).fill(9)

function toDerSignature(raw: Uint8Array): Uint8Array {
  const half = raw.byteLength / 2
  const int = (v: Uint8Array) => {
    let s = 0
    while (s < v.length - 1 && v[s] === 0) s++
    const t = v.subarray(s)
    const body = t[0]! & 0x80 ? Uint8Array.of(0, ...t) : t
    return Uint8Array.of(0x02, body.length, ...body)
  }
  const r = int(raw.subarray(0, half))
  const s = int(raw.subarray(half))
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s)
}

async function authority() {
  const rootKeys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const alg = { name: 'ECDSA', hash: 'SHA-256' }
  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test FIDO Root',
    notBefore: new Date(Date.now() - 86_400_000),
    notAfter: new Date(Date.now() + 86_400_000 * 365),
    signingAlgorithm: alg,
    keys: rootKeys,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  })
  const leafKeys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const aaguidExt = new x509.Extension('1.3.6.1.4.1.45724.1.1.4', false, Uint8Array.of(0x04, 0x10, ...AAGUID))
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=Test Authenticator',
    issuer: root.subject,
    notBefore: new Date(Date.now() - 86_400_000),
    notAfter: new Date(Date.now() + 86_400_000 * 30),
    signingAlgorithm: alg,
    publicKey: leafKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions: [aaguidExt],
  })
  return { root, leaf, leafKeys }
}

async function skKey(application = 'ssh:'): Promise<{ key: SshPublicKey; raw: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  const blob = new SshWriter().string('sk-ssh-ed25519@openssh.com').string(raw).string(application).toBytes()
  return { key: await parseAuthorizedKey(`sk-ssh-ed25519@openssh.com ${btoa(String.fromCharCode(...blob))} yubikey`), raw }
}

async function attestationFile(raw: Uint8Array, opts: { application?: string; aaguid?: Uint8Array; challenge?: Uint8Array<ArrayBuffer>; auth?: Awaited<ReturnType<typeof authority>>; cbor?: boolean } = {}) {
  const auth = opts.auth ?? (await authority())
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(opts.application ?? 'ssh:')))
  const credId = new Uint8Array(32).fill(3)
  const cose = Uint8Array.of(0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20, ...raw)
  const authdata = Uint8Array.of(...rpIdHash, 0x41, 0, 0, 0, 1, ...(opts.aaguid ?? AAGUID), 0, credId.length, ...credId, ...cose)
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', opts.challenge ?? CHALLENGE))
  const signed = new Uint8Array([...authdata, ...hash])
  const signature = toDerSignature(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, auth.leafKeys.privateKey, signed)))
  const file = new SshWriter()
    .string('ssh-sk-attest-v01')
    .string(new Uint8Array(auth.leaf.rawData))
    .string(signature)
    .string(opts.cbor ? cborBytes(authdata) : authdata)
    .uint32(0)
    .string(new Uint8Array(0))
    .toBytes()
  return { file, auth, extra_roots: [auth.root.toString('pem')] }
}

/** A CBOR byte string (major type 2) around data, the way libfido2 hands authenticator data to OpenSSH. */
function cborBytes(data: Uint8Array): Uint8Array {
  const n = data.byteLength
  const header = n < 24 ? [0x40 | n] : n < 256 ? [0x58, n] : [0x59, n >> 8, n & 0xff]
  return Uint8Array.of(...header, ...data)
}

describe('FIDO attestation', () => {
  it('accepts the CBOR-wrapped authenticator data that ssh-keygen writes', async () => {
    const { key, raw } = await skKey()
    const { file, extra_roots } = await attestationFile(raw, { cbor: true })
    const result = await verifyFidoAttestation({ attestation: file, key, challenge: CHALLENGE, extra_roots })
    expect(result.aaguid).toBe('0102030405060708090a0b0c0d0e0f10')
    expect(result.user_present).toBe(true)
  })

  it('accepts a genuine attestation for the key', async () => {
    const { key, raw } = await skKey()
    const { file, extra_roots } = await attestationFile(raw)
    const result = await verifyFidoAttestation({ attestation: file, key, challenge: CHALLENGE, extra_roots })
    expect(result.aaguid).toBe('0102030405060708090a0b0c0d0e0f10')
    expect(result.certificate_subject).toContain('Test Authenticator')
    expect(result.user_present).toBe(true)
  })

  it('refuses a certificate that does not chain to a trusted root', async () => {
    const { key, raw } = await skKey()
    const { file } = await attestationFile(raw)
    await expect(verifyFidoAttestation({ attestation: file, key, challenge: CHALLENGE })).rejects.toMatchObject({ code: 'untrusted_ssh_attestation', message: expect.stringContaining('Yubico root') })
  })

  it('refuses an attestation made for another key', async () => {
    const { key } = await skKey()
    const other = await skKey()
    const { file, extra_roots } = await attestationFile(other.raw)
    await expect(verifyFidoAttestation({ attestation: file, key, challenge: CHALLENGE, extra_roots })).rejects.toThrow(/different key/)
  })

  it('refuses a wrong challenge, a forged signature and another application', async () => {
    const { key, raw } = await skKey()
    const { file, extra_roots } = await attestationFile(raw)
    await expect(verifyFidoAttestation({ attestation: file, key, challenge: new Uint8Array(32).fill(1), extra_roots })).rejects.toThrow(/signature does not verify/)
    const wrongApp = await skKey('ssh:other')
    const forged = await attestationFile(wrongApp.raw, { application: 'ssh:' })
    await expect(verifyFidoAttestation({ attestation: forged.file, key: wrongApp.key, challenge: CHALLENGE, extra_roots: forged.extra_roots })).rejects.toThrow(/another application/)
  })

  it('refuses an attestation whose model does not match the certificate', async () => {
    const { key, raw } = await skKey()
    const { file, extra_roots } = await attestationFile(raw, { aaguid: new Uint8Array(16).fill(0xee) })
    await expect(verifyFidoAttestation({ attestation: file, key, challenge: CHALLENGE, extra_roots })).rejects.toThrow(/different authenticator model/)
  })

  it('refuses garbage and non-security keys', async () => {
    const { key } = await skKey()
    await expect(verifyFidoAttestation({ attestation: new Uint8Array([1, 2, 3]), key, challenge: CHALLENGE })).rejects.toMatchObject({ code: 'invalid_ssh_attestation' })
    const plain = await parseAuthorizedKey(`ssh-ed25519 ${btoa(String.fromCharCode(...new SshWriter().string('ssh-ed25519').string(new Uint8Array((await crypto.subtle.exportKey('raw', ((await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair).publicKey)))).toBytes()))}`)
    await expect(verifyFidoAttestation({ attestation: new Uint8Array(1), key: plain, challenge: CHALLENGE })).rejects.toMatchObject({ code: 'invalid_ssh_attestation' })
  })
})

describe('bundled Yubico trust anchors', () => {
  it('parse, and every intermediate is signed by a bundled root', async () => {
    const { YUBICO_FIDO_INTERMEDIATES, YUBICO_FIDO_ROOTS } = await import('../src/ssh/yubico-roots')
    const roots = YUBICO_FIDO_ROOTS.map((pem) => new x509.X509Certificate(pem))
    expect(roots.map((r) => r.subject)).toEqual(['CN=Yubico U2F Root CA Serial 457200631', 'CN=Yubico FIDO Root CA Serial 450203556', 'CN=Yubico Attestation Root 1'])
    const intermediates = YUBICO_FIDO_INTERMEDIATES.map((pem) => new x509.X509Certificate(pem))
    const [a, b] = intermediates
    expect(a!.subject).toContain('Intermediate A')
    const attestationRoot = roots[2]!
    expect(await a!.verify({ publicKey: attestationRoot.publicKey, signatureOnly: true })).toBe(true)
    expect(await b!.verify({ publicKey: attestationRoot.publicKey, signatureOnly: true })).toBe(true)
    // The FIDO attestation CAs hang below the intermediates.
    expect(await intermediates[2]!.verify({ publicKey: a!.publicKey, signatureOnly: true })).toBe(true)
    expect(await intermediates[3]!.verify({ publicKey: b!.publicKey, signatureOnly: true })).toBe(true)
  })
})
