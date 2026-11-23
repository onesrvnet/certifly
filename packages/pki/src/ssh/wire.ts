import { bytes } from '../encoding'
import { PkiError } from '../errors'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

/** Builds the SSH wire format of RFC 4251 §5: big-endian integers and length-prefixed strings. */
export class SshWriter {
  readonly #parts: Uint8Array[] = []

  byte(value: number): this {
    this.#parts.push(new Uint8Array([value & 0xff]))
    return this
  }

  uint32(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new PkiError('invalid_ssh_key', 'uint32 out of range')
    const out = new Uint8Array(4)
    new DataView(out.buffer).setUint32(0, value)
    this.#parts.push(out)
    return this
  }

  uint64(value: bigint): this {
    if (value < 0n || value > 0xffffffffffffffffn) throw new PkiError('invalid_ssh_key', 'uint64 out of range')
    const out = new Uint8Array(8)
    new DataView(out.buffer).setBigUint64(0, value)
    this.#parts.push(out)
    return this
  }

  /** Raw bytes with no length prefix. */
  raw(value: Uint8Array): this {
    this.#parts.push(value)
    return this
  }

  string(value: Uint8Array | string): this {
    const data = typeof value === 'string' ? encoder.encode(value) : value
    this.uint32(data.byteLength)
    this.#parts.push(data)
    return this
  }

  /** A multiple precision integer: big-endian two's complement, no redundant leading bytes. */
  mpint(magnitude: Uint8Array): this {
    let start = 0
    while (start < magnitude.byteLength && magnitude[start] === 0) start++
    const trimmed = magnitude.subarray(start)
    if (trimmed.byteLength === 0) return this.uint32(0)
    const pad = (trimmed[0]! & 0x80) !== 0
    this.uint32(trimmed.byteLength + (pad ? 1 : 0))
    if (pad) this.#parts.push(new Uint8Array([0]))
    this.#parts.push(trimmed)
    return this
  }

  toBytes(): Uint8Array<ArrayBuffer> {
    const total = this.#parts.reduce((n, p) => n + p.byteLength, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const part of this.#parts) {
      out.set(part, offset)
      offset += part.byteLength
    }
    return out
  }
}

/** Reads the SSH wire format. Every read is bounds-checked and failures raise `PkiError`. */
export class SshReader {
  readonly #data: Uint8Array
  #offset = 0

  constructor(data: Uint8Array) {
    this.#data = data
  }

  get remaining(): number {
    return this.#data.byteLength - this.#offset
  }

  get done(): boolean {
    return this.remaining === 0
  }

  #need(count: number): void {
    if (count < 0 || count > this.remaining) throw new PkiError('invalid_ssh_key', 'Truncated SSH data')
  }

  byte(): number {
    this.#need(1)
    return this.#data[this.#offset++]!
  }

  uint32(): number {
    this.#need(4)
    const value = new DataView(this.#data.buffer, this.#data.byteOffset + this.#offset, 4).getUint32(0)
    this.#offset += 4
    return value
  }

  uint64(): bigint {
    this.#need(8)
    const value = new DataView(this.#data.buffer, this.#data.byteOffset + this.#offset, 8).getBigUint64(0)
    this.#offset += 8
    return value
  }

  rawBytes(count: number): Uint8Array<ArrayBuffer> {
    this.#need(count)
    const out = bytes(this.#data.subarray(this.#offset, this.#offset + count))
    this.#offset += count
    return out
  }

  string(): Uint8Array<ArrayBuffer> {
    const length = this.uint32()
    return this.rawBytes(length)
  }

  text(): string {
    try {
      return decoder.decode(this.string())
    } catch {
      throw new PkiError('invalid_ssh_key', 'SSH string is not valid UTF-8')
    }
  }

  /** The magnitude of a non-negative mpint, without the sign byte. */
  mpint(): Uint8Array<ArrayBuffer> {
    const value = this.string()
    if (value.byteLength > 0 && (value[0]! & 0x80) !== 0) throw new PkiError('invalid_ssh_key', 'Negative mpint')
    let start = 0
    while (start < value.byteLength && value[start] === 0) start++
    return bytes(value.subarray(start))
  }

  expectEnd(): void {
    if (!this.done) throw new PkiError('invalid_ssh_key', 'Unexpected trailing SSH data')
  }
}
