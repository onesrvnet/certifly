import { describe, expect, it } from 'vitest'
import { inviteMail, renderMail, signInMail } from '../src/mail-templates'

describe('renderMail', () => {
  const mail = renderMail({
    heading: 'Join <Acme>',
    body: ['Ann & Bob invited you.'],
    code: '123456',
    action: { label: 'Accept invite', url: 'https://pki.example.com/login?a=1&b=2' },
    footer: 'Ignore this if unexpected.',
  })

  it('escapes text and links in the HTML', () => {
    expect(mail.html).toContain('Join &lt;Acme&gt;')
    expect(mail.html).toContain('Ann &amp; Bob invited you.')
    expect(mail.html).toContain('href="https://pki.example.com/login?a=1&amp;b=2"')
    expect(mail.html).not.toContain('<Acme>')
  })

  it('is branded certifly', () => {
    expect(mail.html).toContain('>certifly</p>')
  })

  it('has a plain-text version with the code and link', () => {
    expect(mail.text).toBe(
      'Join <Acme>\n\nAnn & Bob invited you.\n\n123456\n\nAccept invite: https://pki.example.com/login?a=1&b=2\n\nIgnore this if unexpected.',
    )
  })
})

describe('signInMail', () => {
  it('puts the code in the subject, text and HTML, and links to the sign-in page', () => {
    const mail = signInMail({ code: '042913', link: 'https://pki.example.com/signin/email?token=abc' })
    expect(mail.subject).toBe('Your sign-in code: 042913')
    expect(mail.text).toContain('042913')
    expect(mail.text).toContain('https://pki.example.com/signin/email?token=abc')
    expect(mail.html).toContain('042913')
  })

  it('words a confirmation code as such, not as a sign-in', () => {
    const mail = signInMail({ code: '042913', link: 'https://pki.example.com/signin/email?token=abc', purpose: 'reauth' })
    expect(mail.subject).toBe('Your confirmation code: 042913')
    expect(mail.text).toContain('Confirm it is you')
    expect(mail.text).not.toContain('sign-in page')
  })
})

describe('inviteMail', () => {
  it('names who invited, the role and the address to sign in with', () => {
    const mail = inviteMail({ inviter: 'Ann <script>', email: 'bob@example.com', link: 'https://pki.example.com/invite?token=t', role: 'operator' })
    expect(mail.subject).toBe('Ann <script> invited you to certifly')
    expect(mail.text).toContain('as operator')
    expect(mail.text).toContain('bob@example.com')
    expect(mail.html).toContain('Ann &lt;script&gt;')
    expect(mail.html).not.toContain('<script>')
  })
})
