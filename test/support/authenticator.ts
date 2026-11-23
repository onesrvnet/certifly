import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'

/**
 * A software passkey authenticator for tests: answers WebAuthn registration and
 * sign-in options the way a browser + platform authenticator would ("none"
 * attestation, ES256 keys, discoverable credential).
 */

type Cbor = number | string | Uint8Array | Map<number | string, Cbor> | { [key: string]: Cbor }

function head(major: number, length: number): number[] {
  if (length < 24) return [(major << 5) | length]
  if (length < 256) return [(major << 5) | 24, length]
  return [(major << 5) | 25, length >> 8, length & 0xff]
}

/** Just enough CBOR for attestation objects and COSE keys. */
function cbor(value: Cbor): number[] {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') {
    const bytes = [...Buffer.from(value, 'utf8')]
    return [...head(3, bytes.length), ...bytes]
  }
  if (value instanceof Uint8Array) return [...head(2, value.length), ...value]
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value)
  return [...head(5, entries.length), ...entries.flatMap(([k, v]) => [...cbor(k), ...cbor(v)])]
}

const b64url = (bytes: Uint8Array | Buffer) => Buffer.from(bytes).toString('base64url')
const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest()

function counterBytes(counter: number) {
  const bytes = Buffer.alloc(4)
  bytes.writeUInt32BE(counter)
  return bytes
}

export class SoftwareAuthenticator {
  private keys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  readonly credentialId = randomBytes(16)
  private counter = 0
  private userHandle = ''

  constructor(
    private rpId: string,
    /** Page the browser runs the ceremony on. */
    public origin: string,
  ) {}

  private clientData(type: string, challenge: string) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }))
  }

  /** The public key as a COSE key, as the server stores it. */
  cosePublicKey(): Buffer {
    const jwk = this.keys.publicKey.export({ format: 'jwk' })
    const coseKey = new Map<number, Cbor>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x!, 'base64url')],
      [-3, Buffer.from(jwk.y!, 'base64url')],
    ])
    return Buffer.from(cbor(coseKey))
  }

  /** Credential id as base64url, as the server stores it. */
  get credentialIdBase64url() {
    return b64url(this.credentialId)
  }

  /** Response to registration options (navigator.credentials.create). */
  register(options: { challenge: string; user: { id: string } }) {
    this.userHandle = options.user.id
    const idLength = Buffer.alloc(2)
    idLength.writeUInt16BE(this.credentialId.length)
    const authData = Buffer.concat([
      sha256(this.rpId),
      Buffer.from([0x45]), // user present, user verified, attested credential data
      counterBytes(this.counter),
      Buffer.alloc(16),
      idLength,
      this.credentialId,
      this.cosePublicKey(),
    ])
    const attestationObject = Buffer.from(cbor({ fmt: 'none', attStmt: {}, authData }))
    return {
      id: b64url(this.credentialId),
      rawId: b64url(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64url(this.clientData('webauthn.create', options.challenge)),
        attestationObject: b64url(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
    }
  }

  /** Response to sign-in options (navigator.credentials.get); `counter` overrides the signature counter. */
  authenticate(options: { challenge: string }, counter = ++this.counter) {
    const authData = Buffer.concat([sha256(this.rpId), Buffer.from([0x05]), counterBytes(counter)])
    const clientDataJSON = this.clientData('webauthn.get', options.challenge)
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.keys.privateKey)
    return {
      id: b64url(this.credentialId),
      rawId: b64url(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: this.userHandle,
      },
      clientExtensionResults: {},
    }
  }
}
