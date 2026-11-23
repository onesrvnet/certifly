/** Save text (a PEM file, say) under `filename` in the browser. */
export function downloadText(filename: string, text: string, type = 'application/x-pem-file') {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

/**
 * Read a certificate file as PEM text: PEM files as they are, DER files (a binary `.crt` or
 * `.der`) wrapped into PEM, so the server always gets text.
 */
export async function readCertificateFile(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const text = new TextDecoder().decode(bytes)
  if (text.includes('-----BEGIN')) return text
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  const base64 = btoa(binary).replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`
}

/** Save bytes (a DER certificate, a PKCS#12 file) under `filename` in the browser. */
export function downloadBytes(filename: string, bytes: Uint8Array, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

/** The DER bytes of the first PEM block: its base64 body, decoded. */
export function pemToDer(pem: string): Uint8Array {
  const body = pem.match(/-----BEGIN [A-Z0-9 ]+-----([\s\S]*?)-----END [A-Z0-9 ]+-----/)?.[1] ?? ''
  const binary = atob(body.replace(/\s+/g, ''))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** Bytes from base64 text, e.g. a PKCS#12 file the server sent once. */
export function base64ToBytes(text: string): Uint8Array {
  const binary = atob(text)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** A file name from a certificate's name: `api.example.com` stays, `*.example.com` becomes `wildcard.example.com`. */
export function certificateFileName(name: string | null | undefined): string {
  const safe = (name ?? '').replace(/^\*\./, 'wildcard.').replace(/[^a-zA-Z0-9.-]+/g, '-').replace(/^-+|-+$/g, '')
  return safe || 'certificate'
}

/** Read a CSR file as PEM text: PEM as it is, DER wrapped into a CERTIFICATE REQUEST block. */
export async function readCsrFile(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const text = new TextDecoder().decode(bytes)
  if (text.includes('-----BEGIN')) return text
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  const base64 = btoa(binary).replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
  return `-----BEGIN CERTIFICATE REQUEST-----\n${base64}\n-----END CERTIFICATE REQUEST-----\n`
}
