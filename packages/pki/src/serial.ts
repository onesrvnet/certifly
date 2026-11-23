import { toHex } from './encoding'

/**
 * A certificate serial number: 20 random bytes (the RFC 5280 §4.1.2.2 maximum) with the top bit
 * cleared so the DER INTEGER stays positive, and never zero. Lowercase hex, 40 digits.
 */
export function generateSerial(): string {
  const serial = new Uint8Array(20)
  do {
    crypto.getRandomValues(serial)
    serial[0]! &= 0x7f
  } while (serial.every((b) => b === 0))
  return toHex(serial)
}

/** Serial numbers compared by value, so `00ab` and `ab` are the same serial. */
export function normalizeSerial(serial: string): string {
  const hex = serial.toLowerCase().replace(/^0+/, '')
  return hex === '' ? '0' : hex
}
