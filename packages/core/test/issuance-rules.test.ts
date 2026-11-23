import { describe, expect, it } from 'vitest'
import { effectiveStatus, sanViolations } from '../src/certificates'
import { ValidationError } from '../src/errors'
import { type Actor, certificatePolicy, tagPolicy, templatePolicy } from '../src/policies'
import { checkTemplateSettings, TEMPLATE_PRESETS, type TemplateRow } from '../src/templates'

const actor = (role: Actor['role'], kind: Actor['kind'] = 'session'): Actor => ({ id: `${role}-1`, role, kind, reauth_at: null })

describe('template and certificate policies', () => {
  it('lets every role read, and only admins in a session change templates', () => {
    expect(templatePolicy.abilities(actor('admin'), undefined)).toEqual({ read: true, create: true, update: true, archive: true })
    for (const who of [actor('admin', 'api_key'), actor('operator'), actor('viewer')]) {
      expect(templatePolicy.abilities(who, undefined)).toEqual({ read: true, create: false, update: false, archive: false })
    }
  })

  it('lets every role read tags and only admin sessions manage them', () => {
    expect(tagPolicy.abilities(actor('admin'), undefined)).toEqual({ read: true, create: true, update: true, delete: true })
    for (const who of [actor('admin', 'api_key'), actor('operator'), actor('viewer')]) {
      expect(tagPolicy.abilities(who, undefined)).toEqual({ read: true, create: false, update: false, delete: false })
    }
  })

  it('lets operators and admins issue, renew, revoke and import, with API keys too', () => {
    for (const who of [actor('admin'), actor('operator'), actor('operator', 'api_key')]) {
      expect(certificatePolicy.abilities(who, undefined)).toEqual({ read: true, update: true, issue: true, renew: true, revoke: true, import: true })
    }
    expect(certificatePolicy.abilities(actor('viewer'), undefined)).toEqual({ read: true, update: false, issue: false, renew: false, revoke: false, import: false })
  })
})

describe('template settings', () => {
  const web = { ...TEMPLATE_PRESETS.webserver_tls, allowed_dns: ['**.Example.TEST.'] }

  it('normalises patterns and ranges', () => {
    const settings = checkTemplateSettings({ ...web, allowed_san_types: ['dns', 'ip'], allowed_ips: ['10.0.0.0/8', '10.0.0.0/8', 'fd00:0::/8'] })
    expect(settings.allowed_dns).toEqual(['**.example.test'])
    expect(settings.allowed_ips).toEqual(['10.0.0.0/8', 'fd00::/8'])
  })

  it('refuses regexes, an empty rule list for an enabled SAN type, and usages EC keys cannot have', () => {
    const code = (overrides: object) => {
      try {
        checkTemplateSettings({ ...web, ...overrides })
        return null
      } catch (error) {
        return error instanceof ValidationError ? error.code : String(error)
      }
    }
    expect(code({ allowed_dns: ['.*\\.example\\.test'] })).toBe('invalid_domain_pattern')
    expect(code({ allowed_dns: [] })).toBe('allowed_dns_required')
    expect(code({ allowed_san_types: ['ip'], allowed_ips: [] })).toBe('allowed_ips_required')
    expect(code({ key_usages: ['key_encipherment'] })).toBe('invalid_key_usages')
    expect(code({ key_usages: ['key_encipherment'], key_algorithms: ['rsa-2048'] })).toBeNull()
    expect(code({ require_common_name: true, allowed_subject_fields: [] })).toBe('common_name_not_allowed')
  })
})

describe('SAN rules', () => {
  const template = {
    ...TEMPLATE_PRESETS.mtls_client,
    allowed_san_types: ['dns', 'ip', 'email', 'uri'],
    allowed_dns: ['example.test', '*.svc.example.test'],
    allowed_ips: ['10.0.0.0/8'],
  } as unknown as TemplateRow

  it('matches DNS names, IPs, email domains and URI hosts against the rules', () => {
    expect(
      sanViolations(template, [
        { type: 'dns', value: 'api.svc.example.test' },
        { type: 'ip', value: '10.1.2.3' },
        { type: 'email', value: 'ops@example.test' },
        { type: 'uri', value: 'spiffe://example.test/workload' },
      ]),
    ).toEqual([])
    expect(
      sanViolations(template, [
        { type: 'dns', value: 'a.b.svc.example.test' },
        { type: 'ip', value: '192.168.0.1' },
        { type: 'email', value: 'ops@other.test' },
        { type: 'uri', value: 'spiffe://other.test/workload' },
        { type: 'uri', value: 'urn:uuid:1234' },
        { type: 'dns', value: '*.svc.example.test' },
      ]),
    ).toEqual([
      { san: 'dns:a.b.svc.example.test', reason: 'san_not_allowed' },
      { san: 'ip:192.168.0.1', reason: 'san_not_allowed' },
      { san: 'email:ops@other.test', reason: 'san_not_allowed' },
      { san: 'uri:spiffe://other.test/workload', reason: 'san_not_allowed' },
      { san: 'uri:urn:uuid:1234', reason: 'san_not_allowed' },
      { san: 'dns:*.svc.example.test', reason: 'wildcard_not_allowed' },
    ])
    expect(sanViolations({ ...template, allow_wildcards: true }, [{ type: 'dns', value: '*.svc.example.test' }])).toEqual([])
    expect(sanViolations({ ...template, allowed_san_types: ['dns'] }, [{ type: 'ip', value: '10.0.0.1' }])).toEqual([{ san: 'ip:10.0.0.1', reason: 'san_type_not_allowed' }])
  })
})

describe('certificate status', () => {
  it('reads active certificates past notAfter as expired', () => {
    const now = new Date('2026-06-01T00:00:00Z')
    expect(effectiveStatus({ status: 'active', not_after: new Date('2026-05-31T23:59:59Z') }, now)).toBe('expired')
    expect(effectiveStatus({ status: 'active', not_after: new Date('2026-06-01T00:00:01Z') }, now)).toBe('active')
    expect(effectiveStatus({ status: 'superseded', not_after: new Date('2026-01-01T00:00:00Z') }, now)).toBe('superseded')
  })
})
