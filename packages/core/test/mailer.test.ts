import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createMailer } from '../src/mailer'

const mail = { to: 'ann@example.com', subject: 'Hello', text: 'Body' }

afterEach(() => vi.restoreAllMocks())

describe('createMailer', () => {
  it('writes mails to the outbox directory when one is set', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'certifly-outbox-'))
    try {
      await createMailer({ MAIL_OUTBOX_DIR: dir, SMTP_FROM: 'certifly <ca@example.com>' }).send(mail)
      const files = await readdir(dir)
      expect(files).toHaveLength(1)
      expect(JSON.parse(await readFile(join(dir, files[0]!), 'utf8'))).toEqual({ from: 'certifly <ca@example.com>', ...mail })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('uses a certifly sender by default', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'certifly-outbox-'))
    try {
      await createMailer({ MAIL_OUTBOX_DIR: dir }).send(mail)
      const [file] = await readdir(dir)
      expect(JSON.parse(await readFile(join(dir, file!), 'utf8')).from).toBe('certifly <no-reply@localhost>')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('logs whole mails to the console during development when nothing is configured', async () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => {})
    const mailer = createMailer({ NODE_ENV: 'development' })
    expect(mailer.delivers).toBe(true)
    await mailer.send(mail)
    expect(info).toHaveBeenCalledOnce()
    expect(String(info.mock.calls[0]![0])).toContain('ann@example.com')
    expect(String(info.mock.calls[0]![0])).toContain('Body')
  })

  it('sends nothing in production without SMTP, and logs no body', async () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const mailer = createMailer({ NODE_ENV: 'production' })
    expect(mailer.delivers).toBe(false)
    await mailer.send({ ...mail, subject: 'Your sign-in code: 123456', html: '<p>Body</p>' })
    expect(info).not.toHaveBeenCalled()
    const logged = warn.mock.calls.flat().map(String).join(' ')
    expect(logged).toContain('ann@example.com')
    expect(logged).not.toContain('Body')
    expect(logged).not.toContain('123456')
  })

  it('delivers in production when SMTP is configured', () => {
    expect(createMailer({ NODE_ENV: 'production', SMTP_URL: 'smtp://localhost:2525' }).delivers).toBe(true)
  })
})
