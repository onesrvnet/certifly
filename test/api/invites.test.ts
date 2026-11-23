import { setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { createPgBossQueue } from '../../packages/core/src/jobs-pgboss'
import { Client, addUser, query, resetState, sentMails, serverOptions, setupAdmin, signInWithCode, waitForMail } from '../helpers'

describe('invites', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('lets an admin invite someone, who joins with the invited role', async () => {
    const admin = await setupAdmin()
    const created = await admin.rpc('invites.create', { email: 'Ann@Example.com', role: 'operator' })
    expect(created.status).toBe(200)
    expect(created.body.data).toMatchObject({ email: 'ann@example.com', role: 'operator', status: 'pending' })
    expect(JSON.stringify(created.body)).not.toContain('token')

    const mail = await waitForMail('ann@example.com', (m) => /\/invite\?token=/.test(m.text))
    const token = mail.text.match(/token=([\w-]+)/)![1]!
    const ann = new Client()
    const accepted = await ann.rpc('invite_acceptances.create', { token, name: 'Ann Lee' })
    expect(accepted.status).toBe(200)
    expect((await ann.rpc('sessions.get')).body.data.user).toMatchObject({ email: 'ann@example.com', name: 'Ann Lee', role: 'operator' })
    expect((await admin.rpc('invites.list', { status: 'accepted' })).body.data).toHaveLength(1)
  })

  it('lets an invited address sign in by email code', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'bob@example.com', role: 'viewer' })
    const { client, result } = await signInWithCode('bob@example.com')
    expect(result.status).toBe(200)
    expect((await client.rpc('sessions.get')).body.data.user.role).toBe('viewer')
    // The invite mail is sent by a background job; let it land before the next test clears the outbox.
    await waitForMail('bob@example.com', (m) => /token=/.test(m.text))
  })

  it('shows what an invite link offers without accepting it, and nothing for a bad link', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'cara@example.com', role: 'operator' })
    const token = (await waitForMail('cara@example.com', (m) => /token=/.test(m.text))).text.match(/token=([\w-]+)/)![1]!

    const preview = await new Client().rpc('invite_acceptances.get', { token })
    expect(preview.status).toBe(200)
    expect(preview.body.data).toMatchObject({ email: 'cara@example.com', role: 'operator', inviter_name: expect.any(String) })
    // Looking does not use the invite up.
    expect((await admin.rpc('invites.list', { status: 'pending' })).body.data).toHaveLength(1)

    const bad = await new Client().rpc('invite_acceptances.get', { token: 'not-a-real-token' })
    expect(bad.status).toBe(404)
    expect(bad.body.error.code).toBe('invalid_invite')
  })

  it('refuses an invite link twice', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'bob@example.com' })
    const token = (await waitForMail('bob@example.com', (m) => /token=/.test(m.text))).text.match(/token=([\w-]+)/)![1]!
    expect((await new Client().rpc('invite_acceptances.create', { token })).status).toBe(200)
    const again = await new Client().rpc('invite_acceptances.create', { token })
    expect(again.status).toBe(404)
    expect(again.body.error.code).toBe('invalid_invite')
  })

  it('refuses revoked and expired invites', async () => {
    const admin = await setupAdmin()
    const revoked = (await admin.rpc('invites.create', { email: 'revoked@example.com' })).body.data
    const revokedToken = (await waitForMail('revoked@example.com', (m) => /token=/.test(m.text))).text.match(/token=([\w-]+)/)![1]!
    expect((await admin.rpc('invites.delete', { id: revoked.id })).status).toBe(200)
    expect((await new Client().rpc('invite_acceptances.create', { token: revokedToken })).body.error.code).toBe('invalid_invite')
    expect((await admin.rpc('invites.delete', { id: revoked.id })).status).toBe(404)

    await admin.rpc('invites.create', { email: 'late@example.com' })
    const lateToken = (await waitForMail('late@example.com', (m) => /token=/.test(m.text))).text.match(/token=([\w-]+)/)![1]!
    await query()`update invites set expires_at = now() - interval '1 minute' where email = 'late@example.com'`
    expect((await new Client().rpc('invite_acceptances.create', { token: lateToken })).body.error.code).toBe('invalid_invite')
    expect((await admin.rpc('invites.list', { status: 'expired' })).body.data).toHaveLength(1)
  })

  it('replaces an earlier pending invite for the same address', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'bob@example.com', role: 'viewer' })
    await admin.rpc('invites.create', { email: 'bob@example.com', role: 'operator' })
    const pending = (await admin.rpc('invites.list', { status: 'pending' })).body.data
    expect(pending).toHaveLength(1)
    expect(pending[0].role).toBe('operator')
  })

  it('refuses to invite someone who already has an account', async () => {
    const admin = await setupAdmin()
    const { status, body } = await admin.rpc('invites.create', { email: 'admin@example.com' })
    expect(status).toBe(409)
    expect(body.error.code).toBe('user_exists')
  })

  it('refuses non-admins: they cannot invite, list or revoke', async () => {
    const admin = await setupAdmin()
    const invite = (await admin.rpc('invites.create', { email: 'pending@example.com' })).body.data
    for (const role of ['operator', 'viewer'] as const) {
      const user = await addUser(admin, `${role}@example.com`, role)
      expect((await user.rpc('invites.create', { email: `x-${role}@example.com` })).status).toBe(403)
      expect((await user.rpc('invites.list')).status).toBe(403)
      expect((await user.rpc('invites.delete', { id: invite.id })).status).toBe(403)
    }
    expect(await sentMails('x-operator@example.com')).toHaveLength(0)
    expect((await new Client().rpc('invites.list')).status).toBe(401)
  })

  it('shows invite permissions to admins', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'bob@example.com' })
    const [invite] = (await admin.rpc('invites.list')).body.data
    expect(invite.permissions).toMatchObject({ read: true, create: true, revoke: true })
  })

  it('leaves a single pending invite when two invites for one address arrive at once', async () => {
    const admin = await setupAdmin()
    const results = await Promise.all([
      admin.rpc('invites.create', { email: 'bob@example.com', role: 'viewer' }),
      admin.rpc('invites.create', { email: 'BOB@example.com', role: 'operator' }),
    ])
    for (const { status } of results) expect([200, 409]).toContain(status)
    expect(results.some((r) => r.status === 200)).toBe(true)
    const rows = await query()`select id from invites where email = 'bob@example.com' and accepted_at is null`
    expect(rows).toHaveLength(1)
    await waitForMail('bob@example.com')
  })

  it('deletes the mail job, and so the invite link, as soon as the mail is sent', async () => {
    const admin = await setupAdmin()
    await admin.rpc('invites.create', { email: 'bob@example.com' })
    await waitForMail('bob@example.com', (m) => /token=/.test(m.text))
    const deadline = Date.now() + 10_000
    let left = Infinity
    while (Date.now() < deadline) {
      left = (await query()`select id from pgboss.job where name = 'mail.send'`).length
      if (left === 0) break
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    expect(left).toBe(0)
    // Whatever the worker does not delete itself is swept within minutes, not days.
    const [queue] = await query()`select deletion_seconds, retention_seconds from pgboss.queue where name = 'mail.send'`
    expect(queue).toEqual({ deletion_seconds: 60, retention_seconds: 1800 })
  })

  it('brings the mail queue settings up to date on a queue that already existed', async () => {
    await setupAdmin()
    // As a queue created by an older version would be: deletion off, a week of retention.
    await query()`update pgboss.queue set deletion_seconds = 0, retention_seconds = 604800 where name = 'mail.send'`
    const queue = await createPgBossQueue({ connection_string: process.env.DATABASE_URL!, on_error: () => {} })
    await queue.stop()
    const [row] = await query()`select deletion_seconds, retention_seconds from pgboss.queue where name = 'mail.send'`
    expect(row).toEqual({ deletion_seconds: 60, retention_seconds: 1800 })
  })
})
