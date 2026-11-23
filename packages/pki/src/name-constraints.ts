import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import { bytes } from './encoding'
import { PkiError } from './errors'
import { cidrOverlaps, cidrWithin, formatCidr, ipInCidr, isValidDnsName, isValidEmail, parseCidr, parseDn, type San } from './names'
import * as x509 from './x509'

// Name constraints (RFC 5280 §4.2.1.10) for the three name forms certifly issues and checks:
// DNS names, IP ranges and email addresses.

export const NAME_CONSTRAINTS_OID = '2.5.29.30'

export interface NameConstraintSet {
  /** `example.com` covers the domain and its subdomains; `.example.com` only its subdomains. */
  dns: string[]
  /** CIDR ranges, e.g. `10.0.0.0/8`, `fd00::/8`. */
  ip: string[]
  /** A mailbox (`ops@example.com`), a host (`example.com`) or any subdomain host (`.example.com`). */
  email: string[]
}

export interface NameConstraints {
  permitted: NameConstraintSet
  excluded: NameConstraintSet
}

export interface NameConstraintsInput {
  permitted?: Partial<NameConstraintSet>
  excluded?: Partial<NameConstraintSet>
}

export interface ParsedNameConstraints extends NameConstraints {
  critical: boolean
  /**
   * Constraint forms certifly does not evaluate, e.g. `permitted:uri` or `excluded:directoryName`.
   * Checks fail closed when one of these could apply.
   */
  unsupported: string[]
}

type Kind = keyof NameConstraintSet
const KINDS: readonly Kind[] = ['dns', 'ip', 'email']

// GeneralName tags (RFC 5280 §4.2.1.6).
const GN_EMAIL = 1
const GN_DNS = 2
const GN_IP = 7
const GN_NAMES: Record<number, string> = { 0: 'otherName', 1: 'email', 2: 'dns', 3: 'x400Address', 4: 'directoryName', 5: 'ediPartyName', 6: 'uri', 7: 'ip', 8: 'registeredID' }

// ---------------------------------------------------------------------------------------------
// Normalising input

function normalizeDnsConstraint(value: string): string {
  const text = String(value).trim().toLowerCase().replace(/\.$/, '')
  const name = text.startsWith('.') ? text.slice(1) : text
  if (!isValidDnsName(name)) throw new PkiError('invalid_name_constraints', `Not a valid DNS constraint: ${value}`)
  return text
}

function normalizeIpConstraint(value: string): string {
  const cidr = parseCidr(String(value))
  if (!cidr) throw new PkiError('invalid_name_constraints', `Not a valid CIDR (host bits must be zero): ${value}`)
  return formatCidr(cidr)
}

function normalizeEmailConstraint(value: string): string {
  const text = String(value).trim()
  if (text.includes('@')) {
    const at = text.lastIndexOf('@')
    const email = `${text.slice(0, at)}@${text.slice(at + 1).toLowerCase()}`
    if (!isValidEmail(email)) throw new PkiError('invalid_name_constraints', `Not a valid email constraint: ${value}`)
    return email
  }
  return normalizeDnsConstraint(text)
}

const NORMALIZE: Record<Kind, (v: string) => string> = { dns: normalizeDnsConstraint, ip: normalizeIpConstraint, email: normalizeEmailConstraint }

function normalizeSet(set: Partial<NameConstraintSet> | undefined): NameConstraintSet {
  const out: NameConstraintSet = { dns: [], ip: [], email: [] }
  for (const kind of KINDS) {
    const values = set?.[kind] ?? []
    if (!Array.isArray(values)) throw new PkiError('invalid_name_constraints', `${kind} constraints must be a list`)
    out[kind] = [...new Set(values.map(NORMALIZE[kind]))]
  }
  return out
}

/** Validates and normalises constraints (lowercase DNS, canonical CIDRs, no duplicates). */
export function normalizeNameConstraints(input: NameConstraintsInput | null | undefined): NameConstraints {
  return { permitted: normalizeSet(input?.permitted), excluded: normalizeSet(input?.excluded) }
}

export function isEmptyNameConstraints(nc: NameConstraintsInput | null | undefined): boolean {
  const n = normalizeNameConstraints(nc)
  return KINDS.every((k) => n.permitted[k].length === 0 && n.excluded[k].length === 0)
}

export function hasPermittedSubtrees(nc: NameConstraints): boolean {
  return KINDS.some((k) => nc.permitted[k].length > 0)
}

// ---------------------------------------------------------------------------------------------
// Encoding and parsing

function ipConstraintBytes(value: string): Uint8Array {
  const cidr = parseCidr(value)!
  const mask = new Uint8Array(cidr.address.byteLength)
  for (let bit = 0; bit < cidr.prefix; bit++) mask[bit >> 3]! |= 0x80 >> (bit & 7)
  const out = new Uint8Array(cidr.address.byteLength * 2)
  out.set(cidr.address)
  out.set(mask, cidr.address.byteLength)
  return out
}

function subtrees(set: NameConstraintSet): pkijs.GeneralSubtree[] {
  const names: pkijs.GeneralName[] = [
    ...set.dns.map((value) => new pkijs.GeneralName({ type: GN_DNS, value })),
    ...set.ip.map((value) => new pkijs.GeneralName({ type: GN_IP, value: new asn1js.OctetString({ valueHex: bytes(ipConstraintBytes(value)) }) })),
    ...set.email.map((value) => new pkijs.GeneralName({ type: GN_EMAIL, value })),
  ]
  return names.map((base) => new pkijs.GeneralSubtree({ base }))
}

/** The NameConstraints extension, always critical as RFC 5280 §4.2.1.10 requires. */
export function nameConstraintsExtension(input: NameConstraintsInput): x509.Extension {
  const nc = normalizeNameConstraints(input)
  if (isEmptyNameConstraints(nc)) throw new PkiError('invalid_name_constraints', 'Name constraints need at least one permitted or excluded entry')
  const permitted = subtrees(nc.permitted)
  const excluded = subtrees(nc.excluded)
  const value = new pkijs.NameConstraints({
    ...(permitted.length ? { permittedSubtrees: permitted } : {}),
    ...(excluded.length ? { excludedSubtrees: excluded } : {}),
  })
  return new x509.Extension(NAME_CONSTRAINTS_OID, true, bytes(value.toSchema().toBER(false)))
}

function maskToPrefix(mask: Uint8Array): number | null {
  let prefix = 0
  let ended = false
  for (const byte of mask) {
    for (let bit = 7; bit >= 0; bit--) {
      const set = (byte >> bit) & 1
      if (set && ended) return null
      if (set) prefix++
      else ended = true
    }
  }
  return prefix
}

function readSubtrees(list: pkijs.GeneralSubtree[] | undefined, side: 'permitted' | 'excluded', unsupported: string[]): NameConstraintSet {
  const set: NameConstraintSet = { dns: [], ip: [], email: [] }
  for (const subtree of list ?? []) {
    const { type, value } = subtree.base
    const minimum = typeof subtree.minimum === 'number' ? subtree.minimum : subtree.minimum.valueBlock.valueDec
    // RFC 5280 §4.2.1.10: minimum MUST be zero and maximum absent; anything else is not evaluated.
    if (minimum !== 0 || subtree.maximum !== undefined) {
      unsupported.push(`${side}:${GN_NAMES[type] ?? type}`)
      continue
    }
    if (type === GN_DNS && typeof value === 'string') set.dns.push(value.toLowerCase())
    else if (type === GN_EMAIL && typeof value === 'string') set.email.push(value)
    else if (type === GN_IP && value instanceof asn1js.OctetString) {
      const raw = value.valueBlock.valueHexView
      const half = raw.byteLength / 2
      const prefix = half === 4 || half === 16 ? maskToPrefix(raw.subarray(half)) : null
      if (prefix === null) unsupported.push(`${side}:ip`)
      else {
        const address = new Uint8Array(raw.subarray(0, half))
        // Clear host bits so the range is canonical even if the issuer left them set.
        for (let bit = prefix; bit < half * 8; bit++) address[bit >> 3]! &= ~(0x80 >> (bit & 7))
        set.ip.push(formatCidr({ address, prefix }))
      }
    } else unsupported.push(`${side}:${GN_NAMES[type] ?? type}`)
  }
  return set
}

/** The certificate's NameConstraints extension, or null when it has none. */
export function readNameConstraints(cert: x509.X509Certificate): ParsedNameConstraints | null {
  const ext = cert.getExtension(NAME_CONSTRAINTS_OID)
  if (!ext) return null
  const asn = asn1js.fromBER(ext.value)
  if (asn.offset === -1) throw new PkiError('invalid_certificate', 'The NameConstraints extension is malformed')
  let parsed: pkijs.NameConstraints
  try {
    parsed = new pkijs.NameConstraints({ schema: asn.result })
  } catch {
    throw new PkiError('invalid_certificate', 'The NameConstraints extension is malformed')
  }
  const unsupported: string[] = []
  const permitted = readSubtrees(parsed.permittedSubtrees, 'permitted', unsupported)
  const excluded = readSubtrees(parsed.excludedSubtrees, 'excluded', unsupported)
  return { critical: ext.critical, permitted, excluded, unsupported: [...new Set(unsupported)] }
}

// ---------------------------------------------------------------------------------------------
// Matching

/** Whether a DNS name (possibly `*.x`) lies in a DNS constraint subtree. */
function dnsInSubtree(name: string, constraint: string): boolean {
  if (constraint.startsWith('.')) return name.endsWith(constraint)
  return name === constraint || name.endsWith(`.${constraint}`)
}

/** Whether a wildcard name could expand into the excluded subtree (e.g. `*.a.com` vs `x.a.com`). */
function wildcardMeetsSubtree(name: string, constraint: string): boolean {
  if (!name.startsWith('*.')) return false
  const base = name.slice(2)
  const c = constraint.startsWith('.') ? constraint.slice(1) : constraint
  return c.endsWith(`.${base}`) && c.split('.').length === base.split('.').length + 1
}

/** Whether every name in DNS subtree `inner` is also in subtree `outer`. */
function dnsSubtreeWithin(inner: string, outer: string): boolean {
  if (outer.startsWith('.')) return inner.endsWith(outer)
  const bare = inner.startsWith('.') ? inner.slice(1) : inner
  return bare === outer || bare.endsWith(`.${outer}`)
}

interface EmailForm {
  kind: 'mailbox' | 'host' | 'subdomain'
  value: string
  domain: string
}

function emailForm(constraint: string): EmailForm {
  if (constraint.includes('@')) return { kind: 'mailbox', value: constraint, domain: constraint.slice(constraint.lastIndexOf('@') + 1).toLowerCase() }
  if (constraint.startsWith('.')) return { kind: 'subdomain', value: constraint, domain: constraint.slice(1).toLowerCase() }
  return { kind: 'host', value: constraint, domain: constraint.toLowerCase() }
}

function emailInSubtree(email: string, constraint: string): boolean {
  const c = emailForm(constraint)
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase()
  if (c.kind === 'mailbox') return emailForm(email).value === c.value
  if (c.kind === 'host') return domain === c.domain
  return domain.endsWith(`.${c.domain}`)
}

function emailSubtreeWithin(inner: string, outer: string): boolean {
  const a = emailForm(inner)
  const b = emailForm(outer)
  if (b.kind === 'mailbox') return a.kind === 'mailbox' && a.value === b.value
  if (b.kind === 'host') return a.kind !== 'subdomain' && a.domain === b.domain
  return a.domain.endsWith(`.${b.domain}`) || (a.kind === 'subdomain' && a.domain === b.domain)
}

const WITHIN: Record<Kind, (inner: string, outer: string) => boolean> = { dns: dnsSubtreeWithin, ip: cidrWithin, email: emailSubtreeWithin }
const OVERLAPS: Record<Kind, (a: string, b: string) => boolean> = {
  dns: (a, b) => dnsSubtreeWithin(a, b) || dnsSubtreeWithin(b, a),
  ip: cidrOverlaps,
  email: (a, b) => emailSubtreeWithin(a, b) || emailSubtreeWithin(b, a),
}

export interface NameConstraintViolation {
  name: string
  type: 'dns' | 'ip' | 'email' | 'uri' | 'subject'
  reason: 'excluded' | 'not_permitted' | 'unsupported_constraint'
}

/**
 * Checks names against an issuer's constraints. The subject's CN is checked as a DNS name when
 * it looks like a host name, and its emailAddress as an email, as relying parties may do either.
 */
export function checkNameConstraints(nc: ParsedNameConstraints | NameConstraints, names: { sans: readonly San[]; subject?: string | null }): NameConstraintViolation[] {
  const unsupported = 'unsupported' in nc ? nc.unsupported : []
  const violations: NameConstraintViolation[] = []
  const subject = names.subject ? parseDn(names.subject) : []
  const candidates: { type: Kind | 'uri'; value: string }[] = [...names.sans]
  for (const attr of subject) {
    // Like OpenSSL, only a CN with a dot counts as a host name; `client-1` is just a label.
    const cn = attr.value.toLowerCase()
    if (attr.type === 'CN' && cn.includes('.') && isValidDnsName(cn, { allowWildcard: true })) candidates.push({ type: 'dns', value: cn })
    if (attr.type === 'E' && isValidEmail(attr.value)) candidates.push({ type: 'email', value: attr.value })
  }

  if (subject.length > 0 && unsupported.some((u) => u.endsWith(':directoryName'))) {
    violations.push({ name: names.subject!, type: 'subject', reason: 'unsupported_constraint' })
  }

  for (const { type, value } of candidates) {
    if (type === 'uri') {
      if (unsupported.some((u) => u.endsWith(':uri'))) violations.push({ name: value, type, reason: 'unsupported_constraint' })
      continue
    }
    const inSubtree =
      type === 'dns' ? (c: string) => dnsInSubtree(value, c) : type === 'ip' ? (c: string) => ipInCidr(value, c) : (c: string) => emailInSubtree(value, c)
    const excludedHit = nc.excluded[type].some((c) => inSubtree(c) || (type === 'dns' && wildcardMeetsSubtree(value, c)))
    if (excludedHit) {
      violations.push({ name: value, type, reason: 'excluded' })
      continue
    }
    // Any permitted subtree of a form restricts that form; an IPv6 SAN under IPv4-only ranges
    // is refused, as OpenSSL does.
    if (nc.permitted[type].length > 0 && !nc.permitted[type].some(inSubtree)) violations.push({ name: value, type, reason: 'not_permitted' })
  }
  return violations
}

/**
 * Problems that keep `child` from being a subset of `parent`. The child must restrict every name
 * form the parent restricts, only to names the parent permits, and keep everything the parent
 * excludes out. That way the issuing CA's own constraints are enough to check a leaf against.
 */
export function nameConstraintsSubsetProblems(child: NameConstraints, parent: ParsedNameConstraints | NameConstraints): string[] {
  const problems: string[] = []
  if ('unsupported' in parent && parent.unsupported.length > 0) {
    problems.push(`The parent uses constraint forms certifly cannot check: ${parent.unsupported.join(', ')}`)
  }
  for (const kind of KINDS) {
    if (parent.permitted[kind].length > 0) {
      if (child.permitted[kind].length === 0) problems.push(`The parent restricts ${kind} names, so the child must permit a subset of: ${parent.permitted[kind].join(', ')}`)
      for (const c of child.permitted[kind]) {
        if (!parent.permitted[kind].some((p) => WITHIN[kind](c, p))) problems.push(`Permitted ${kind} ${c} is outside the parent's permitted names`)
      }
    }
    for (const e of parent.excluded[kind]) {
      const stillExcluded = child.excluded[kind].some((x) => WITHIN[kind](e, x))
      const unreachable = child.permitted[kind].length > 0 && !child.permitted[kind].some((p) => OVERLAPS[kind](p, e))
      if (!stillExcluded && !unreachable) problems.push(`The parent excludes ${kind} ${e}; the child must exclude it too`)
    }
  }
  return problems
}

export interface RuleConstraintProblem {
  /** The template rule: a domain pattern or a CIDR. */
  rule: string
  type: 'dns' | 'ip'
  reason: 'excluded' | 'not_permitted' | 'unsupported_constraint'
}

/** The DNS subtree a domain pattern stands for: an exact name, or every name below a suffix. */
function patternSubtree(pattern: string): { exact: string } | { below: string } {
  const [first, ...rest] = pattern.split('.')
  return first === '*' || first === '**' ? { below: rest.join('.') } : { exact: pattern }
}

/**
 * Checks a template's matching rules against its CA's name constraints, so that a template can
 * never promise names the CA cannot sign. Every name a domain pattern (`api.example.com`,
 * `*.svc.example.com`, `**.example.com`) or CIDR covers must be permitted (when the CA permits
 * that form at all) and none may be excluded outright. A rule that only partly overlaps an
 * excluded subtree passes; issuance still refuses the excluded names themselves.
 */
export function ruleConstraintProblems(nc: ParsedNameConstraints | NameConstraints, rules: { dns: readonly string[]; ip: readonly string[] }): RuleConstraintProblem[] {
  const unsupported = 'unsupported' in nc ? nc.unsupported : []
  const problems: RuleConstraintProblem[] = []
  for (const rule of rules.dns) {
    if (unsupported.some((u) => u.endsWith(':dns'))) {
      problems.push({ rule, type: 'dns', reason: 'unsupported_constraint' })
      continue
    }
    const subtree = patternSubtree(rule)
    const covered = (c: string) => ('exact' in subtree ? dnsInSubtree(subtree.exact, c) : dnsSubtreeWithin(`.${subtree.below}`, c))
    if (nc.excluded.dns.some(covered)) problems.push({ rule, type: 'dns', reason: 'excluded' })
    else if (nc.permitted.dns.length > 0 && !nc.permitted.dns.some(covered)) problems.push({ rule, type: 'dns', reason: 'not_permitted' })
  }
  for (const rule of rules.ip) {
    if (unsupported.some((u) => u.endsWith(':ip'))) {
      problems.push({ rule, type: 'ip', reason: 'unsupported_constraint' })
      continue
    }
    if (nc.excluded.ip.some((c) => cidrWithin(rule, c))) problems.push({ rule, type: 'ip', reason: 'excluded' })
    else if (nc.permitted.ip.length > 0 && !nc.permitted.ip.some((c) => cidrWithin(rule, c))) problems.push({ rule, type: 'ip', reason: 'not_permitted' })
  }
  return problems
}
