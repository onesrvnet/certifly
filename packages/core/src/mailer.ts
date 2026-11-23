import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import nodemailer from 'nodemailer'

export interface Mail {
  to: string
  subject: string
  text: string
  html?: string
}

export interface Mailer {
  /**
   * Whether mails reach their recipient (or a stand-in a developer can read). False in
   * production without SMTP: features that need mail are then switched off or fall back.
   */
  readonly delivers: boolean
  send(mail: Mail): Promise<void>
}

export interface MailerConfig {
  NODE_ENV?: string
  SMTP_URL?: string
  SMTP_FROM?: string
  /** When set, mails are written as JSON files into this directory instead of being sent. */
  MAIL_OUTBOX_DIR?: string
}

/**
 * Create the mailer for the current environment: SMTP when configured, an on-disk outbox for
 * tests, the console during development. In production without SMTP nothing is sent, and the
 * log only says that a mail was dropped: its body can hold sign-in codes and invite links.
 */
export function createMailer(config: MailerConfig): Mailer {
  const from = config.SMTP_FROM ?? 'certifly <no-reply@localhost>'

  if (config.MAIL_OUTBOX_DIR) {
    const dir = config.MAIL_OUTBOX_DIR
    return {
      delivers: true,
      async send(mail) {
        await mkdir(dir, { recursive: true })
        const file = `${Date.now()}-${Math.random().toString(36).slice(2)}.json`
        await writeFile(join(dir, file), JSON.stringify({ from, ...mail }))
      },
    }
  }

  if (config.SMTP_URL) {
    const transport = nodemailer.createTransport(config.SMTP_URL)
    return {
      delivers: true,
      async send(mail) {
        await transport.sendMail({ from, ...mail })
      },
    }
  }

  if (config.NODE_ENV !== 'production') {
    return {
      delivers: true,
      async send(mail) {
        console.info(`[mail] to=${mail.to} subject=${JSON.stringify(mail.subject)}\n${mail.text}`)
      },
    }
  }

  return {
    delivers: false,
    async send(mail) {
      console.warn(`[mail] not sent, SMTP_URL is not set: to=${mail.to}`)
    },
  }
}
