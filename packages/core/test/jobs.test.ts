import { describe, expect, it, vi } from 'vitest'
import type { Context } from '../src/context'
import { JOB_NAMES, type Job, runJob, SCHEDULES } from '../src/jobs'

describe('runJob', () => {
  it('sends the mail of a mail.send job', async () => {
    const send = vi.fn(async () => {})
    const ctx = { mailer: { send } } as unknown as Context
    await runJob(ctx, { name: 'mail.send', data: { to: 'ann@example.com', subject: 'Hi', text: 'Body' } })
    expect(send).toHaveBeenCalledWith({ to: 'ann@example.com', subject: 'Hi', text: 'Body' })
  })

  it('lets a failing handler fail the job, so the queue retries it', async () => {
    const ctx = { mailer: { send: async () => Promise.reject(new Error('smtp down')) } } as unknown as Context
    await expect(runJob(ctx, { name: 'mail.send', data: { to: 'a@b.c', subject: 's', text: 't' } })).rejects.toThrow('smtp down')
  })

  it('refuses unknown jobs', async () => {
    await expect(runJob({} as Context, { name: 'nope', data: {} } as unknown as Job)).rejects.toThrow('Unknown job: nope')
  })
})

describe('job lists', () => {
  it('names every job once', () => {
    expect(new Set(JOB_NAMES).size).toBe(JOB_NAMES.length)
    expect([...JOB_NAMES].sort()).toEqual([
      'acme.validate_challenge',
      'alerts.deliver',
      'alerts.event',
      'alerts.scan_expiry',
      'ca_keys.rewrap',
      'cleanup.expired',
      'crls.rebuild',
      'crls.rebuild_due',
      'mail.send',
    ])
  })

  it('schedules only known jobs', () => {
    for (const schedule of SCHEDULES) expect(JOB_NAMES).toContain(schedule.name)
  })
})
