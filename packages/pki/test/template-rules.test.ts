import { describe, expect, it } from 'vitest'
import { normalizeNameConstraints, ruleConstraintProblems } from '../src/index'

const nc = normalizeNameConstraints({
  permitted: { dns: ['example.test', '.svc.corp.test'], ip: ['10.0.0.0/8'] },
  excluded: { dns: ['secret.example.test'], ip: ['10.99.0.0/16'] },
})

describe('template rules inside name constraints', () => {
  it('accepts exact names and patterns that stay inside the permitted subtrees', () => {
    expect(ruleConstraintProblems(nc, { dns: ['example.test', 'api.example.test', '*.example.test', '**.example.test', '*.a.svc.corp.test'], ip: ['10.1.0.0/16', '10.0.0.1/32'] })).toEqual([])
  })

  it('refuses rules outside the permitted subtrees', () => {
    expect(ruleConstraintProblems(nc, { dns: ['other.test', '*.test', 'svc.corp.test'], ip: ['192.168.0.0/16', '0.0.0.0/0', 'fd00::/8'] })).toEqual([
      { rule: 'other.test', type: 'dns', reason: 'not_permitted' },
      { rule: '*.test', type: 'dns', reason: 'not_permitted' },
      // `.svc.corp.test` only covers names below svc.corp.test, not the name itself.
      { rule: 'svc.corp.test', type: 'dns', reason: 'not_permitted' },
      { rule: '192.168.0.0/16', type: 'ip', reason: 'not_permitted' },
      { rule: '0.0.0.0/0', type: 'ip', reason: 'not_permitted' },
      { rule: 'fd00::/8', type: 'ip', reason: 'not_permitted' },
    ])
  })

  it('refuses rules that lie wholly in an excluded subtree, and lets partial overlaps through', () => {
    expect(ruleConstraintProblems(nc, { dns: ['secret.example.test', '*.secret.example.test', '**.example.test'], ip: ['10.99.1.0/24', '10.0.0.0/8'] })).toEqual([
      { rule: 'secret.example.test', type: 'dns', reason: 'excluded' },
      { rule: '*.secret.example.test', type: 'dns', reason: 'excluded' },
      { rule: '10.99.1.0/24', type: 'ip', reason: 'excluded' },
    ])
  })

  it('leaves a name form the CA does not restrict open', () => {
    const dnsOnly = normalizeNameConstraints({ permitted: { dns: ['example.test'] } })
    expect(ruleConstraintProblems(dnsOnly, { dns: [], ip: ['192.168.0.0/16'] })).toEqual([])
    expect(ruleConstraintProblems(normalizeNameConstraints({}), { dns: ['anything.test'], ip: ['0.0.0.0/0'] })).toEqual([])
  })

  it('fails closed on constraint forms certifly cannot evaluate', () => {
    const parsed = { ...nc, critical: true, unsupported: ['permitted:dns'] }
    expect(ruleConstraintProblems(parsed, { dns: ['api.example.test'], ip: [] })).toEqual([{ rule: 'api.example.test', type: 'dns', reason: 'unsupported_constraint' }])
  })
})
