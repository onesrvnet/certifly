import { describe, expect, it } from 'vitest'
import {
  buildDn,
  checkNameConstraints,
  cidrWithin,
  dnEquals,
  formatIp,
  generateSerial,
  ipInCidr,
  isValidDnsName,
  isValidDomainPattern,
  matchesDomainPattern,
  nameConstraintsSubsetProblems,
  normalizeNameConstraints,
  normalizeSan,
  parseCidr,
  parseDn,
  parseIp,
  PkiError,
} from '../src/index'

describe('serials', () => {
  it('are 20 random bytes, positive and non-zero', () => {
    const serials = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const serial = generateSerial()
      expect(serial).toMatch(/^[0-7][0-9a-f]{39}$/)
      expect(/^0+$/.test(serial)).toBe(false)
      serials.add(serial)
    }
    expect(serials.size).toBe(200)
  })
})

describe('distinguished names', () => {
  it('builds and parses names without hand escaping', () => {
    const dn = buildDn([
      { type: 'CN', value: 'Example, Inc. + Co' },
      { type: 'O', value: 'Ünïcode Org' },
      { type: 'C', value: 'DE' },
    ])
    expect(parseDn(dn)).toEqual([
      { type: 'CN', value: 'Example, Inc. + Co' },
      { type: 'O', value: 'Ünïcode Org' },
      { type: 'C', value: 'DE' },
    ])
  })

  it('compares names case-insensitively with folded whitespace', () => {
    expect(dnEquals('CN=Example  CA, O=Acme', 'CN=example ca, O=ACME')).toBe(true)
    expect(dnEquals('CN=Example CA, O=Acme', 'O=Acme, CN=Example CA')).toBe(false)
  })

  it('refuses bad attributes', () => {
    expect(() => parseDn('C=Germany')).toThrow(PkiError)
    expect(() => buildDn([{ type: 'XX', value: 'a' }])).toThrow(/Unknown name attribute/)
    expect(() => parseDn('garbage')).toThrow(PkiError)
  })
})

describe('SAN validation', () => {
  it('accepts and normalises valid names', () => {
    expect(normalizeSan({ type: 'dns', value: 'API.Example.test.' })).toEqual({ type: 'dns', value: 'api.example.test' })
    expect(normalizeSan({ type: 'dns', value: '*.example.test' })).toEqual({ type: 'dns', value: '*.example.test' })
    expect(normalizeSan({ type: 'ip', value: '2001:DB8:0:0:0:0:0:1' })).toEqual({ type: 'ip', value: '2001:db8::1' })
    expect(normalizeSan({ type: 'email', value: 'Ops@Example.TEST' })).toEqual({ type: 'email', value: 'Ops@example.test' })
    expect(normalizeSan({ type: 'uri', value: 'spiffe://example.test/ns/default/sa/web' }).value).toBe('spiffe://example.test/ns/default/sa/web')
  })

  it.each([
    ['dns', 'exa mple.test'],
    ['dns', '-bad.example.test'],
    ['dns', 'a.*.example.test'],
    ['dns', '*.test'],
    ['dns', 'ünicode.test'],
    ['dns', `${'a'.repeat(64)}.test`],
    ['ip', '256.1.1.1'],
    ['ip', '010.1.1.1'],
    ['ip', '1:2:3:4:5:6:7:8:9'],
    ['ip', '1::2::3'],
    ['email', 'no-at-sign'],
    ['email', 'a@b@c.test'],
    ['uri', 'not a uri'],
    ['uri', '/relative/path'],
  ] as const)('refuses %s %s', (type, value) => {
    expect(() => normalizeSan({ type, value })).toThrow(PkiError)
  })

  it('parses and formats IP addresses', () => {
    expect(formatIp(parseIp('::ffff:192.0.2.1')!)).toBe('::ffff:c000:201')
    expect(formatIp(parseIp('2001:db8:0:1:0:0:0:1')!)).toBe('2001:db8:0:1::1')
    expect(formatIp(parseIp('10.0.0.1')!)).toBe('10.0.0.1')
    expect(parseIp('::')).toEqual(new Uint8Array(16))
  })

  it('validates DNS names with and without wildcards', () => {
    expect(isValidDnsName('localhost')).toBe(true)
    expect(isValidDnsName('*.example.test')).toBe(false)
    expect(isValidDnsName('*.example.test', { allowWildcard: true })).toBe(true)
    expect(isValidDnsName('xn--bcher-kva.example')).toBe(true)
  })
})

describe('domain patterns', () => {
  it('matches exact, one-label and any-depth patterns', () => {
    expect(matchesDomainPattern('api.example.test', 'api.example.test')).toBe(true)
    expect(matchesDomainPattern('a.example.test', '*.example.test')).toBe(true)
    expect(matchesDomainPattern('a.b.example.test', '*.example.test')).toBe(false)
    expect(matchesDomainPattern('example.test', '*.example.test')).toBe(false)
    expect(matchesDomainPattern('a.b.example.test', '**.example.test')).toBe(true)
    expect(matchesDomainPattern('example.test', '**.example.test')).toBe(false)
    expect(matchesDomainPattern('evilexample.test', '**.example.test')).toBe(false)
  })

  it('only lets wildcard names through wildcard patterns', () => {
    expect(matchesDomainPattern('*.example.test', '*.example.test')).toBe(true)
    expect(matchesDomainPattern('*.svc.example.test', '**.example.test')).toBe(true)
    expect(matchesDomainPattern('*.example.test', 'a.example.test')).toBe(false)
  })

  it('refuses malformed patterns', () => {
    expect(isValidDomainPattern('*.test')).toBe(false)
    expect(isValidDomainPattern('a*.example.test')).toBe(false)
    expect(isValidDomainPattern('.*')).toBe(false)
    expect(isValidDomainPattern('**.example.test')).toBe(true)
  })
})

describe('CIDR matching', () => {
  it('parses ranges and refuses set host bits', () => {
    expect(parseCidr('10.0.0.0/8')).not.toBeNull()
    expect(parseCidr('10.0.0.1/8')).toBeNull()
    expect(parseCidr('fd00::/8')).not.toBeNull()
    expect(parseCidr('10.0.0.0/33')).toBeNull()
  })

  it('matches addresses and nested ranges', () => {
    expect(ipInCidr('10.1.2.3', '10.0.0.0/8')).toBe(true)
    expect(ipInCidr('11.0.0.1', '10.0.0.0/8')).toBe(false)
    expect(ipInCidr('fd00::1', 'fd00::/8')).toBe(true)
    expect(ipInCidr('::ffff:10.0.0.1', '10.0.0.0/8')).toBe(false)
    expect(cidrWithin('10.1.0.0/16', '10.0.0.0/8')).toBe(true)
    expect(cidrWithin('10.0.0.0/8', '10.1.0.0/16')).toBe(false)
  })
})

describe('name constraints', () => {
  const nc = {
    ...normalizeNameConstraints({
      permitted: { dns: ['example.test', '.other.test'], ip: ['10.0.0.0/8'], email: ['example.test'] },
      excluded: { dns: ['secret.example.test'], ip: ['10.66.0.0/16'] },
    }),
    critical: true,
    unsupported: [],
  }

  it('permits names inside the permitted subtrees', () => {
    const sans = [
      { type: 'dns', value: 'example.test' },
      { type: 'dns', value: 'a.b.example.test' },
      { type: 'dns', value: 'x.other.test' },
      { type: 'ip', value: '10.1.2.3' },
      { type: 'email', value: 'ops@example.test' },
    ] as const
    expect(checkNameConstraints(nc, { sans: [...sans], subject: 'CN=api.example.test' })).toEqual([])
  })

  it('refuses names outside or excluded', () => {
    const violations = checkNameConstraints(nc, {
      sans: [
        { type: 'dns', value: 'other.test' },
        { type: 'dns', value: 'evil.test' },
        { type: 'dns', value: 'db.secret.example.test' },
        { type: 'dns', value: '*.example.test' },
        { type: 'ip', value: '10.66.1.1' },
        { type: 'ip', value: 'fd00::1' },
        { type: 'email', value: 'ops@sub.example.test' },
      ],
      subject: 'CN=evil.test',
    })
    expect(violations.map((v) => `${v.reason}:${v.name}`)).toEqual([
      'not_permitted:other.test',
      'not_permitted:evil.test',
      'excluded:db.secret.example.test',
      'excluded:*.example.test',
      'excluded:10.66.1.1',
      'not_permitted:fd00::1',
      'not_permitted:ops@sub.example.test',
      'not_permitted:evil.test',
    ])
  })

  it('fails closed on constraint forms it cannot evaluate', () => {
    const odd = { ...nc, unsupported: ['permitted:uri', 'excluded:directoryName'] }
    const violations = checkNameConstraints(odd, { sans: [{ type: 'uri', value: 'spiffe://example.test/x' }], subject: 'CN=client-1' })
    expect(violations.map((v) => v.reason)).toEqual(['unsupported_constraint', 'unsupported_constraint'])
  })

  it('accepts a narrower child and refuses a wider one', () => {
    const narrower = normalizeNameConstraints({ permitted: { dns: ['svc.example.test'], ip: ['10.1.0.0/16'], email: ['ops@example.test'] } })
    expect(nameConstraintsSubsetProblems(narrower, nc)).toEqual([])

    const wider = normalizeNameConstraints({ permitted: { dns: ['example.test', 'evil.test'], ip: ['10.0.0.0/8'] } })
    const problems = nameConstraintsSubsetProblems(wider, nc)
    expect(problems.join('\n')).toMatch(/evil\.test is outside/)
    expect(problems.join('\n')).toMatch(/restricts email/)
    expect(problems.join('\n')).toMatch(/excludes dns secret\.example\.test/)
    expect(problems.join('\n')).toMatch(/excludes ip 10\.66\.0\.0\/16/)
  })

  it('validates constraint input', () => {
    expect(() => normalizeNameConstraints({ permitted: { ip: ['10.0.0.1/8'] } })).toThrow(/host bits/)
    expect(() => normalizeNameConstraints({ permitted: { dns: ['not a domain'] } })).toThrow(PkiError)
  })
})
