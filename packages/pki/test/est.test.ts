import { describe, expect, it } from 'vitest'
import { buildEstCertificates, buildRootCertificate, certificateToPem, decodeEstRequestBody, parseCsr, parseForwardedClientCertificate, pemEncode } from '../src/index'
import * as x509 from '../src/x509'
import { caKey, daysFromNow } from './helpers'

async function rootCertificate(name: string) {
  const key = await caKey('ecdsa-p256')
  return { key, cert: await buildRootCertificate({ signer: key.signer, public_key_spki: key.public_key_spki, subject: `CN=${name}`, not_after: daysFromNow(30), path_length: null }) }
}

async function request(subject = 'CN=device.est.test') {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: subject, keys, signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } })
  return new Uint8Array(csr.rawData)
}

describe('EST encodings', { timeout: 30_000 }, () => {
  it('builds a base64 certs-only answer that parses back, wrapped in short lines', async () => {
    const a = await rootCertificate('Est A')
    const b = await rootCertificate('Est B')
    const body = buildEstCertificates([a.cert.der, b.cert.der])
    expect(body.endsWith('\n')).toBe(true)
    expect(body.split('\n').every((line) => line.length <= 64)).toBe(true)
    const parsed = new x509.X509Certificates(Buffer.from(body.replace(/\s+/g, ''), 'base64'))
    expect(parsed.map((c) => c.subject)).toEqual(['CN=Est A', 'CN=Est B'])
  })

  it('reads an enrollment body as base64 with or without line breaks, as PEM, or as raw DER', async () => {
    const der = await request()
    const b64 = Buffer.from(der).toString('base64')
    const wrapped = b64.replace(/.{1,64}/g, '$&\r\n')
    for (const body of [b64, wrapped, `\n  ${wrapped}  `, pemEncode(der, 'CERTIFICATE REQUEST'), der, new TextEncoder().encode(wrapped)]) {
      const parsed = await parseCsr(decodeEstRequestBody(body))
      expect(parsed.subject).toBe('CN=device.est.test')
    }
    expect(() => decodeEstRequestBody('')).toThrow()
    expect(() => decodeEstRequestBody('not base64!')).toThrow()
  })
})

describe('forwarded client certificates', { timeout: 30_000 }, () => {
  it('accepts what Traefik, nginx and Caddy send', async () => {
    const { cert } = await rootCertificate('Est Client')
    const other = (await rootCertificate('Est Other')).cert
    const der = Buffer.from(cert.der)
    const b64 = der.toString('base64')
    const pem = certificateToPem(cert.der)
    const cases: Record<string, string> = {
      // Traefik passTLSClientCert pem: the PEM body on one line, no delimiters; a chain is comma separated.
      traefik: b64,
      traefikChain: `${b64},${Buffer.from(other.der).toString('base64')}`,
      // nginx $ssl_client_escaped_cert
      nginx: encodeURIComponent(pem),
      pem,
      pemOnOneLine: pem.replace(/\n/g, ' '),
      urlEncodedBase64: encodeURIComponent(b64),
      quoted: `"${b64}"`,
    }
    for (const [name, value] of Object.entries(cases)) {
      expect(Buffer.from(parseForwardedClientCertificate(value)).equals(der), name).toBe(true)
    }
  })

  it('refuses empty, garbled and non-certificate values', async () => {
    const der = await request()
    for (const value of ['', '   ', '!!!', 'AAAA', '%E0%A4%A', Buffer.from(der).toString('base64'), pemEncode(der, 'CERTIFICATE REQUEST')]) {
      expect(() => parseForwardedClientCertificate(value), value).toThrow()
    }
  })
})
