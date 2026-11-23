/** Overwrites a buffer we own, so decrypted key material does not linger until GC. */
export function wipe(...buffers: (Uint8Array | ArrayBuffer | undefined | null)[]): void {
  for (const buffer of buffers) {
    if (!buffer) continue
    ;(buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)).fill(0)
  }
}

/** A fresh copy backed by a plain ArrayBuffer, the type WebCrypto accepts. */
export function copy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.byteLength)
  out.set(bytes)
  return out
}

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.byteLength
  }
  return out
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Strict hex decoding; returns null for anything that is not an even run of hex digits. */
export function fromHex(text: string): Uint8Array<ArrayBuffer> | null {
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) return null
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** Strict base64 or base64url decoding; returns null on malformed input. */
export function fromBase64(text: string): Uint8Array<ArrayBuffer> | null {
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return null
  const unpadded = normalized.replace(/=+$/, '')
  if (unpadded.length % 4 === 1) return null
  try {
    const binary = atob(unpadded + '='.repeat((4 - (unpadded.length % 4)) % 4))
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Constant-time comparison for equal-length inputs. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
