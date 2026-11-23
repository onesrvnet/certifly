export interface MailContent {
  heading: string
  /** Paragraphs of plain text; escaped for HTML. */
  body: string[]
  /** A one-time code shown in a large box. */
  code?: string
  action?: { label: string; url: string }
  /** Small print below the action. */
  footer?: string
}

const escape = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const FONT = `-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif`

/** Render a transactional mail as a simple branded HTML page plus its plain-text version. */
export function renderMail(content: MailContent): { text: string; html: string } {
  const text = [
    content.heading,
    '',
    ...content.body.flatMap((line) => [line, '']),
    ...(content.code ? [content.code, ''] : []),
    ...(content.action ? [`${content.action.label}: ${content.action.url}`, ''] : []),
    ...(content.footer ? [content.footer] : []),
  ]
    .join('\n')
    .trim()

  const paragraphs = content.body
    .map((line) => `<p style="margin:0 0 16px;font-size:15px;line-height:24px;color:#3f3f46">${escape(line)}</p>`)
    .join('')
  const code = content.code
    ? `<div style="margin:8px 0 24px;padding:16px;border-radius:8px;background:#f4f4f5;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:28px;font-weight:600;letter-spacing:6px;color:#18181b">${escape(content.code)}</div>`
    : ''
  const action = content.action
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 24px"><tr><td style="border-radius:8px;background:#18181b">` +
      `<a href="${escape(content.action.url)}" style="display:inline-block;padding:12px 20px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none">${escape(content.action.label)}</a>` +
      `</td></tr></table>` +
      `<p style="margin:0 0 16px;font-size:13px;line-height:20px;color:#71717a">Or copy this link into your browser:<br><a href="${escape(content.action.url)}" style="color:#71717a;word-break:break-all">${escape(content.action.url)}</a></p>`
    : ''
  const footer = content.footer
    ? `<p style="margin:24px 0 0;padding-top:16px;border-top:1px solid #e4e4e7;font-size:13px;line-height:20px;color:#a1a1aa">${escape(content.footer)}</p>`
    : ''

  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(content.heading)}</title></head>
<body style="margin:0;padding:0;background:#fafafa;font-family:${FONT}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fafafa"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border:1px solid #e4e4e7;border-radius:12px"><tr><td style="padding:32px">
<p style="margin:0 0 24px;font-size:18px;line-height:24px;font-weight:700;letter-spacing:-0.2px;color:#18181b">certifly</p>
<h1 style="margin:0 0 16px;font-size:20px;line-height:28px;font-weight:600;color:#18181b">${escape(content.heading)}</h1>
${paragraphs}${code}${action}${footer}
</td></tr></table>
</td></tr></table>
</body></html>`

  return { text, html }
}

/**
 * The mail with a one-time code and link: for signing in, or for confirming it is you
 * before a sensitive change.
 */
export function signInMail(input: { code: string; link: string; purpose?: 'sign_in' | 'reauth' }) {
  const reauth = input.purpose === 'reauth'
  return {
    subject: reauth ? `Your confirmation code: ${input.code}` : `Your sign-in code: ${input.code}`,
    ...renderMail({
      heading: reauth ? 'Confirm it is you' : 'Your code to sign in',
      body: [reauth ? 'Enter this code in certifly to confirm it is you:' : 'Enter this code on the sign-in page:'],
      code: input.code,
      action: { label: 'Open certifly', url: input.link },
      footer: 'The code and link expire in 15 minutes. If you did not request this, you can ignore this email.',
    }),
  }
}

/** The mail that invites someone to join. */
export function inviteMail(input: { inviter: string; email: string; link: string; role: string }) {
  return {
    subject: `${input.inviter} invited you to certifly`,
    ...renderMail({
      heading: 'Join certifly',
      body: [
        `${input.inviter} invited you to join certifly as ${input.role}.`,
        `Sign in with ${input.email} to get started.`,
      ],
      action: { label: 'Accept invite', url: input.link },
      footer: 'The invitation expires in 7 days. If you were not expecting it, you can ignore this email.',
    }),
  }
}
