import { PkiError } from './errors'
import * as x509 from './x509'

// ---------------------------------------------------------------------------------------------
// Distinguished names. Parsing, escaping and encoding are left to x509.Name.

export interface DnAttribute {
  /** Short name (CN, O, OU, C, ST, L, DC, E, ...) or a dotted OID. */
  type: string
  value: string
}

const KNOWN_TYPES = new Set(['CN', 'O', 'OU', 'C', 'ST', 'L', 'DC', 'E', 'SN', 'G', 'T', 'I', 'STREET', 'UID', 'serialNumber'])
const OID = /^\d+(\.\d+)+$/

function checkAttributes(attributes: DnAttribute[]): void {
  for (const { type, value } of attributes) {
    if (!KNOWN_TYPES.has(type) && !OID.test(type)) throw new PkiError('invalid_dn', `Unknown name attribute: ${type}`)
    if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
      throw new PkiError('invalid_dn', `The ${type} attribute must be 1 to 256 characters`)
    }
    if (type === 'C' && !/^[A-Z]{2}$/.test(value)) throw new PkiError('invalid_dn', 'C must be a two-letter country code')
  }
}

function toName(dn: string | DnAttribute[] | x509.Name): x509.Name {
  if (dn instanceof x509.Name) return dn
  if (Array.isArray(dn)) {
    checkAttributes(dn)
    return new x509.Name(dn.map((a) => ({ [a.type]: [a.value] })))
  }
  if (typeof dn !== 'string') throw new PkiError('invalid_dn', 'Expected a distinguished name')
  let name: x509.Name
  try {
    name = new x509.Name(dn)
  } catch {
    throw new PkiError('invalid_dn', 'The distinguished name could not be parsed')
  }
  return name
}

/** Attributes in encoding order. An empty string is the empty name. */
export function parseDn(dn: string | x509.Name): DnAttribute[] {
  if (typeof dn === 'string' && dn.trim() === '') return []
  const name = toName(dn)
  const attributes = name.toJSON().flatMap((rdn) => Object.entries(rdn).flatMap(([type, values]) => values.map((value) => ({ type, value }))))
  if (typeof dn === 'string' && attributes.length === 0) throw new PkiError('invalid_dn', 'The distinguished name has no attributes')
  checkAttributes(attributes)
  return attributes
}

/** An RFC 4514 string for the attributes; x509.Name does the escaping. */
export function buildDn(attributes: DnAttribute[]): string {
  if (attributes.length === 0) return ''
  return toName(attributes).toString()
}

/** Normalises a DN (string or attributes) to the canonical x509.Name form, validating it. */
export function normalizeDn(dn: string | DnAttribute[]): string {
  const attributes = Array.isArray(dn) ? dn : parseDn(dn)
  return buildDn(attributes)
}

/** DER of a name, for building certificates. */
export function dnToName(dn: string | DnAttribute[]): x509.Name {
  return toName(Array.isArray(dn) ? dn : parseDn(dn))
}

/**
 * Name comparison in the spirit of RFC 5280 §7.1: same attributes in the same order, values
 * compared case-insensitively with whitespace folded. String encodings are ignored.
 */
export function dnEquals(a: string | x509.Name, b: string | x509.Name): boolean {
  const left = parseDn(a)
  const right = parseDn(b)
  const fold = (v: string) => v.trim().replace(/\s+/g, ' ').toLowerCase()
  return left.length === right.length && left.every((attr, i) => attr.type === right[i]!.type && fold(attr.value) === fold(right[i]!.value))
}

export function commonName(dn: string | x509.Name): string | null {
  return parseDn(dn).find((a) => a.type === 'CN')?.value ?? null
}

// ---------------------------------------------------------------------------------------------
// Subject alternative names.

export type SanType = 'dns' | 'ip' | 'email' | 'uri'

export interface San {
  type: SanType
  value: string
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/

/**
 * A DNS name in A-label form (RFC 1035 / RFC 5890), lowercase. With `allowWildcard`, the
 * leftmost label may be exactly `*` (RFC 6125 §6.4.3) when at least two labels follow it.
 */
export function isValidDnsName(name: string, { allowWildcard = false } = {}): boolean {
  if (typeof name !== 'string' || name.length === 0 || name.length > 253 || name !== name.toLowerCase()) return false
  const labels = name.split('.')
  if (labels[0] === '*') {
    if (!allowWildcard || labels.length < 3) return false
    labels.shift()
  }
  return labels.every((label) => LABEL.test(label))
}

/** Parses an IPv4 or IPv6 address into its 4 or 16 bytes; null when it is not one. */
export function parseIp(text: string): Uint8Array | null {
  if (typeof text !== 'string') return null
  if (text.includes(':')) return parseIpv6(text)
  return parseIpv4(text)
}

function parseIpv4(text: string): Uint8Array | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  const out = new Uint8Array(4)
  for (const [i, part] of parts.entries()) {
    // No leading zeros: "010" is octal to some parsers and decimal to others.
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null
    const value = Number(part)
    if (value > 255) return null
    out[i] = value
  }
  return out
}

function parseIpv6(text: string): Uint8Array | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return null
  const halves = text.split('::')
  if (halves.length > 2) return null
  const groups = (part: string) => (part === '' ? [] : part.split(':'))
  const head = groups(halves[0]!)
  const tail = halves.length === 2 ? groups(halves[1]!) : []
  const words: number[] = []
  const pushGroups = (list: string[], target: number[]) => {
    for (const [i, group] of list.entries()) {
      if (group.includes('.')) {
        // An embedded IPv4 address is only allowed as the last 32 bits.
        if (i !== list.length - 1) return false
        const v4 = parseIpv4(group)
        if (!v4) return false
        target.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!)
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return false
        target.push(Number.parseInt(group, 16))
      }
    }
    return true
  }
  const headWords: number[] = []
  const tailWords: number[] = []
  if (!pushGroups(head, headWords) || !pushGroups(tail, tailWords)) return null
  if (halves.length === 1) {
    if (headWords.length !== 8) return null
    words.push(...headWords)
  } else {
    const missing = 8 - headWords.length - tailWords.length
    if (missing < 1) return null
    words.push(...headWords, ...new Array<number>(missing).fill(0), ...tailWords)
  }
  const out = new Uint8Array(16)
  for (const [i, word] of words.entries()) {
    out[i * 2] = word >> 8
    out[i * 2 + 1] = word & 0xff
  }
  return out
}

/** Canonical text for an address: dotted quad, or RFC 5952 IPv6. */
export function formatIp(address: Uint8Array): string {
  if (address.byteLength === 4) return Array.from(address).join('.')
  if (address.byteLength !== 16) throw new PkiError('invalid_input', 'An IP address is 4 or 16 bytes')
  const words = Array.from({ length: 8 }, (_, i) => (address[i * 2]! << 8) | address[i * 2 + 1]!)
  // RFC 5952 §4.2: compress the longest run of two or more zero groups, the first one on a tie.
  let best = { start: -1, length: 0 }
  for (let i = 0; i < 8; ) {
    if (words[i] !== 0) {
      i++
      continue
    }
    let j = i
    while (j < 8 && words[j] === 0) j++
    if (j - i > best.length && j - i >= 2) best = { start: i, length: j - i }
    i = j
  }
  const hex = words.map((w) => w.toString(16))
  if (best.start < 0) return hex.join(':')
  return `${hex.slice(0, best.start).join(':')}::${hex.slice(best.start + best.length).join(':')}`
}

const EMAIL_LOCAL = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/

/** An RFC 5321 mailbox with a dot-atom local part and a DNS domain. */
export function isValidEmail(email: string): boolean {
  if (typeof email !== 'string' || email.length > 254) return false
  const at = email.lastIndexOf('@')
  if (at < 1) return false
  const local = email.slice(0, at)
  const domain = email.slice(at + 1)
  return local.length <= 64 && EMAIL_LOCAL.test(local) && isValidDnsName(domain.toLowerCase())
}

/** An absolute URI with a scheme, e.g. `https://…` or a SPIFFE ID `spiffe://trust-domain/path`. */
export function isValidUri(uri: string): boolean {
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > 2048 || /\s/.test(uri)) return false
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(uri)) return false
  try {
    new URL(uri)
    return true
  } catch {
    return false
  }
}

/** Validates and normalises one SAN. Throws `invalid_san` with the offending value. */
export function normalizeSan(san: San, { allowWildcard = true } = {}): San {
  const { type, value } = san ?? ({} as San)
  if (typeof value !== 'string') throw new PkiError('invalid_san', 'A SAN value must be a string')
  switch (type) {
    case 'dns': {
      const name = value.trim().toLowerCase().replace(/\.$/, '')
      if (!isValidDnsName(name, { allowWildcard })) throw new PkiError('invalid_san', `Not a valid DNS name: ${value}`, { san })
      return { type, value: name }
    }
    case 'ip': {
      const address = parseIp(value.trim())
      if (!address) throw new PkiError('invalid_san', `Not a valid IP address: ${value}`, { san })
      return { type, value: formatIp(address) }
    }
    case 'email': {
      const at = value.lastIndexOf('@')
      // The domain part is case-insensitive; the local part is kept as given.
      const email = at < 0 ? value : `${value.slice(0, at)}@${value.slice(at + 1).toLowerCase()}`
      if (!isValidEmail(email.trim())) throw new PkiError('invalid_san', `Not a valid email address: ${value}`, { san })
      return { type, value: email.trim() }
    }
    case 'uri':
      if (!isValidUri(value.trim())) throw new PkiError('invalid_san', `Not a valid URI: ${value}`, { san })
      return { type, value: value.trim() }
    default:
      throw new PkiError('invalid_san', `Unsupported SAN type: ${String(type)}`, { san })
  }
}

/** Normalises a list of SANs and drops exact duplicates. */
export function normalizeSans(sans: readonly San[], options?: { allowWildcard?: boolean }): San[] {
  const seen = new Set<string>()
  const out: San[] = []
  for (const san of sans) {
    const normalized = normalizeSan(san, options)
    const key = `${normalized.type}:${normalized.value}`
    if (!seen.has(key)) {
      seen.add(key)
      out.push(normalized)
    }
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Domain patterns and CIDRs: the only matching rules admins can write (no regexes).

/**
 * Checks a pattern: an exact name (`api.example.com`), `*.suffix` for exactly one extra label,
 * or `**.suffix` for one or more extra labels.
 */
export function isValidDomainPattern(pattern: string): boolean {
  if (typeof pattern !== 'string') return false
  const [first, ...rest] = pattern.split('.')
  if (first === '*' || first === '**') return rest.length >= 2 && isValidDnsName(rest.join('.'))
  return isValidDnsName(pattern)
}

/**
 * Whether a DNS name matches a domain pattern. A wildcard SAN (`*.example.com`) only matches
 * patterns that cover every name it stands for, i.e. `*.example.com` or `**.example.com` (or a
 * `**` pattern on a parent domain); an exact pattern never covers a wildcard.
 */
export function matchesDomainPattern(name: string, pattern: string): boolean {
  if (!isValidDomainPattern(pattern) || !isValidDnsName(name, { allowWildcard: true })) return false
  const labels = name.split('.')
  const [first, ...rest] = pattern.split('.')
  const suffix = rest.join('.')
  if (first === '*') return labels.length === rest.length + 1 && labels.slice(1).join('.') === suffix
  if (first === '**') return labels.length > rest.length && labels.slice(labels.length - rest.length).join('.') === suffix
  return name === pattern
}

export interface Cidr {
  address: Uint8Array
  prefix: number
}

/** Parses `10.0.0.0/8` or `fd00::/8`. A bare address is a /32 or /128. Host bits must be zero. */
export function parseCidr(text: string): Cidr | null {
  if (typeof text !== 'string') return null
  const [ip, prefixText, extra] = text.trim().split('/')
  if (extra !== undefined || !ip) return null
  const address = parseIp(ip)
  if (!address) return null
  const max = address.byteLength * 8
  if (prefixText !== undefined && !/^(0|[1-9]\d{0,2})$/.test(prefixText)) return null
  const prefix = prefixText === undefined ? max : Number(prefixText)
  if (prefix > max) return null
  for (let bit = prefix; bit < max; bit++) {
    if (address[bit >> 3]! & (0x80 >> (bit & 7))) return null
  }
  return { address, prefix }
}

export function isValidCidr(text: string): boolean {
  return parseCidr(text) !== null
}

export function formatCidr(cidr: Cidr): string {
  return `${formatIp(cidr.address)}/${cidr.prefix}`
}

function prefixMatches(address: Uint8Array, network: Uint8Array, prefix: number): boolean {
  if (address.byteLength !== network.byteLength) return false
  for (let bit = 0; bit < prefix; bit++) {
    const mask = 0x80 >> (bit & 7)
    if ((address[bit >> 3]! & mask) !== (network[bit >> 3]! & mask)) return false
  }
  return true
}

/** Whether an address lies in a CIDR. IPv4 and IPv6 never match each other. */
export function ipInCidr(ip: string | Uint8Array, cidr: string | Cidr): boolean {
  const address = typeof ip === 'string' ? parseIp(ip) : ip
  const range = typeof cidr === 'string' ? parseCidr(cidr) : cidr
  return !!address && !!range && prefixMatches(address, range.address, range.prefix)
}

/** Whether `inner` is entirely contained in `outer`. */
export function cidrWithin(inner: string | Cidr, outer: string | Cidr): boolean {
  const a = typeof inner === 'string' ? parseCidr(inner) : inner
  const b = typeof outer === 'string' ? parseCidr(outer) : outer
  return !!a && !!b && a.address.byteLength === b.address.byteLength && a.prefix >= b.prefix && prefixMatches(a.address, b.address, b.prefix)
}

/** Whether two ranges share any address. */
export function cidrOverlaps(a: string | Cidr, b: string | Cidr): boolean {
  return cidrWithin(a, b) || cidrWithin(b, a)
}
