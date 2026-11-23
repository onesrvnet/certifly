import type { H3Event } from 'h3'
import { ValidationError } from '@certifly/core/errors'

interface PasskeyChallenge {
  challenge?: string
  kind?: 'register' | 'authenticate'
}

/** The pending WebAuthn challenge between the options and verify steps (5 minutes). */
function challengeSession(event: H3Event) {
  const config = env()
  return useSession<PasskeyChallenge>(event, {
    name: 'certifly_passkey',
    password: config.SECRET_KEY,
    maxAge: 5 * 60,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: config.URL.startsWith('https://'),
      path: '/api',
    },
  })
}

export async function rememberChallenge(event: H3Event, kind: PasskeyChallenge['kind'], challenge: string) {
  await (await challengeSession(event)).update({ kind, challenge })
}

/** Take the pending challenge of this kind; each challenge can be used once. */
export async function takeChallenge(event: H3Event, kind: PasskeyChallenge['kind']): Promise<string> {
  const session = await challengeSession(event)
  const { challenge, kind: stored } = session.data
  await session.clear()
  if (!challenge || stored !== kind) throw new ValidationError('The passkey request expired; try again', 'passkey_expired')
  return challenge
}

/** The origin the browser ran the ceremony on: the instance's own address. */
export function requestOrigin(): string {
  return new URL(env().URL).origin
}
