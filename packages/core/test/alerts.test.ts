import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { describeAlert, thresholdFor, webhookSignature } from '../src/alerts'
import { type Actor, alertPolicy, caPolicy, trustBundlePolicy } from '../src/policies'

const actor = (role: Actor['role'], kind: Actor['kind'] = 'session'): Actor => ({ id: `${role}-1`, role, kind, reauth_at: null })
const DAY = 24 * 60 * 60 * 1000

describe('webhook signatures', () => {
  it('is sha256= and the hex HMAC-SHA256 of the raw body', () => {
    const body = '{"id":"x","timestamp":1700000000}'
    const expected = createHmac('sha256', 'whsec_test').update(body).digest('hex')
    expect(webhookSignature('whsec_test', body)).toBe(`sha256=${expected}`)
    expect(webhookSignature('whsec_test', `${body} `)).not.toBe(`sha256=${expected}`)
  })
})

describe('expiry thresholds', () => {
  const now = new Date('2026-11-22T12:00:00Z')
  const at = (days: number) => new Date(now.getTime() + days * DAY)

  it('picks the nearest threshold the remaining time has reached', () => {
    expect(thresholdFor([30, 7, 1], at(40), now)).toBeNull()
    expect(thresholdFor([30, 7, 1], at(30), now)).toBe(30)
    expect(thresholdFor([30, 7, 1], at(20), now)).toBe(30)
    expect(thresholdFor([30, 7, 1], at(5), now)).toBe(7)
    expect(thresholdFor([1, 30, 7], at(0.5), now)).toBe(1)
  })
})

describe('alert texts', () => {
  const certificate = {
    id: 'c1',
    common_name: 'app.example.test',
    sans: [],
    serial: 'ab',
    not_after: '2026-12-01T00:00:00.000Z',
    issuer_dn: 'CN=Issuing',
    source: 'ui',
    ca: null,
    template: null,
    url: 'http://x/certificates/c1',
  }
  it('names the certificate and the days left', () => {
    const text = describeAlert({ event: 'expiring', test: false, payload: { certificate, days_left: 7 } })
    expect(text.subject).toBe('Certificate app.example.test expires in 7 days')
    expect(text.url).toBe(certificate.url)
    expect(describeAlert({ event: null, test: true, payload: {} }).subject).toBe('Test alert')
  })
})

describe('policies', () => {
  it('lets only admins in a session revoke CAs and change trust bundles and alerts', () => {
    expect(caPolicy.can(actor('admin'), 'revoke', undefined)).toBe(true)
    for (const who of [actor('admin', 'api_key'), actor('operator'), actor('viewer')]) {
      expect(caPolicy.can(who, 'revoke', undefined)).toBe(false)
      expect(trustBundlePolicy.abilities(who, undefined)).toEqual({ read: true, create: false, update: false, delete: false })
      expect(alertPolicy.can(who, 'manage', undefined)).toBe(false)
    }
    expect(trustBundlePolicy.abilities(actor('admin'), undefined)).toEqual({ read: true, create: true, update: true, delete: true })
  })

  it('shows the delivery history to operators but alert settings to admins only', () => {
    expect(alertPolicy.abilities(actor('operator'), undefined)).toEqual({ read: false, manage: false, read_deliveries: true })
    expect(alertPolicy.abilities(actor('viewer'), undefined)).toEqual({ read: false, manage: false, read_deliveries: false })
    expect(alertPolicy.abilities(actor('admin'), undefined)).toEqual({ read: true, manage: true, read_deliveries: true })
  })
})
