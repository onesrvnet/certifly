import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import { bytes, parseCertificate, type CertificateInput } from './encoding'
import { PkiError } from './errors'

const DATA_OID = '1.2.840.113549.1.7.1'
const KEY_BAG_OID = '1.2.840.113549.1.12.10.1.2' // pkcs8ShroudedKeyBag (RFC 7292 §4.2.2)
const CERT_BAG_OID = '1.2.840.113549.1.12.10.1.3' // certBag (RFC 7292 §4.2.3)
const X509_CERT_OID = '1.2.840.113549.1.9.22.1' // x509Certificate
const FRIENDLY_NAME_OID = '1.2.840.113549.1.9.20'
const LOCAL_KEY_ID_OID = '1.2.840.113549.1.9.21'

/**
 * PBKDF2 and MAC iteration count. The MAC key uses the PKCS#12 KDF, so a password can be guessed
 * against either; both get the same work factor. OpenSSL's own default is 2048.
 */
export const PKCS12_ITERATIONS = 100_000

function toPkijsCertificate(input: CertificateInput): pkijs.Certificate {
  return pkijs.Certificate.fromBER(bytes(new Uint8Array(parseCertificate(input).rawData)))
}

/**
 * A degenerate CMS SignedData holding only certificates ("certs-only", RFC 5652 §5.2 and RFC 8551
 * §3.2.2), as served by EST `/cacerts` (RFC 7030 §4.1.3). DER.
 */
export function buildPkcs7CertsOnly(certificates: readonly CertificateInput[]): Uint8Array<ArrayBuffer> {
  if (certificates.length === 0) throw new PkiError('invalid_input', 'At least one certificate is required')
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: DATA_OID }),
    certificates: certificates.map(toPkijsCertificate),
    signerInfos: [],
  })
  const content = new pkijs.ContentInfo({ contentType: pkijs.ContentInfo.SIGNED_DATA, content: signed.toSchema(true) })
  return new Uint8Array(content.toSchema().toBER(false))
}

export interface Pkcs12Params {
  /** A leaf key generated for this request (extractable). Never a CA key. */
  private_key: CryptoKey
  certificate: CertificateInput
  /** Issuer first, then up to the root. */
  chain?: readonly CertificateInput[]
  password: string
  friendly_name?: string
}

function attribute(type: string, value: asn1js.BaseBlock): pkijs.Attribute {
  return new pkijs.Attribute({ type, values: [value] })
}

/**
 * A password-protected PKCS#12 file for the one-time download of a generated leaf key.
 * Modern algorithms only: the key bag and the certificates are encrypted with PBES2
 * (PBKDF2-HMAC-SHA-256, AES-256-CBC; RFC 8018), and the file has an HMAC-SHA-256 MAC
 * (RFC 7292 §5). OpenSSL 3, current Windows and macOS read this.
 */
export async function buildPkcs12(params: Pkcs12Params): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof params.password !== 'string' || params.password.length === 0 || params.password.length > 1024) {
    throw new PkiError('invalid_password', 'The PKCS#12 password must be 1 to 1024 characters')
  }
  const password = bytes(new TextEncoder().encode(params.password))
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', params.private_key))
  try {
    const leaf = toPkijsCertificate(params.certificate)
    const chain = (params.chain ?? []).map(toPkijsCertificate)
    const leafDer = bytes(new Uint8Array(leaf.toSchema().toBER(false)))
    // Ties the key to its certificate for importers; a digest of the certificate, like OpenSSL.
    const localKeyId = new asn1js.OctetString({ valueHex: await crypto.subtle.digest('SHA-1', leafDer) })
    const labels = [
      attribute(LOCAL_KEY_ID_OID, localKeyId),
      ...(params.friendly_name ? [attribute(FRIENDLY_NAME_OID, new asn1js.BmpString({ value: params.friendly_name }))] : []),
    ]
    const encryption = {
      password: password.buffer,
      // pkijs generates a fresh IV (and salt) per encryption; its type still asks for one.
      contentEncryptionAlgorithm: { name: 'AES-CBC', length: 256 } as unknown as pkijs.ContentEncryptionAlgorithm,
      hmacHashAlgorithm: 'SHA-256',
      iterationCount: PKCS12_ITERATIONS,
    }

    const keyBag = new pkijs.PKCS8ShroudedKeyBag({ parsedValue: pkijs.PrivateKeyInfo.fromBER(pkcs8) })
    await keyBag.makeInternalValues(encryption)
    const keyContents = new pkijs.SafeContents({ safeBags: [new pkijs.SafeBag({ bagId: KEY_BAG_OID, bagValue: keyBag, bagAttributes: labels })] })

    const certBags = [leaf, ...chain].map(
      (cert, i) =>
        new pkijs.SafeBag({
          bagId: CERT_BAG_OID,
          bagValue: new pkijs.CertBag({ certId: X509_CERT_OID, parsedValue: cert }),
          ...(i === 0 ? { bagAttributes: labels } : {}),
        }),
    )
    const certContents = new pkijs.SafeContents({ safeBags: certBags })

    // The key bag is already shrouded; the certificate list is encrypted as well, as OpenSSL does.
    const authenticatedSafe = new pkijs.AuthenticatedSafe({
      parsedValue: { safeContents: [{ privacyMode: 0, value: keyContents }, { privacyMode: 1, value: certContents }] },
    })
    await authenticatedSafe.makeInternalValues({ safeContents: [{}, encryption] })

    const pfx = new pkijs.PFX({ parsedValue: { integrityMode: 0, authenticatedSafe } })
    await pfx.makeInternalValues({
      password: password.buffer,
      iterations: PKCS12_ITERATIONS,
      pbkdf2HashAlgorithm: { name: 'SHA-256' },
      hmacHashAlgorithm: 'SHA-256',
    })
    return new Uint8Array(pfx.toSchema().toBER(false))
  } finally {
    pkcs8.fill(0)
    password.fill(0)
  }
}
