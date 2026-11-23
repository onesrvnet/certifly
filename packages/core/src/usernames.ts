import { type Executor, schema } from '@certifly/db'
import { and, eq, sql } from 'drizzle-orm'
import { ConflictError, isUniqueViolation, NotFoundError, ValidationError } from './errors'

/** A Unix-style login: lowercase, starts with a letter or underscore, at most 32 characters. */
export const USERNAME_PATTERN = /^[a-z_][a-z0-9_.-]{0,31}$/

/**
 * Names that are system accounts on most hosts. With an own-username rule a person's username
 * becomes a local login, so these can never be anyone's username.
 */
export const RESERVED_USERNAMES: ReadonlySet<string> = new Set([
  'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc',
  'nobody', 'sshd', 'postgres', 'admin', 'administrator',
])

/** A username candidate from an email address: its local part, cleaned up. Never reserved. */
export function deriveUsername(email: string): string {
  const local = (email.split('@')[0] ?? '').toLowerCase()
  let name = local.replace(/[^a-z0-9_.-]/g, '-')
  if (!name) name = 'user'
  if (!/^[a-z_]/.test(name)) name = `u${name}`
  name = name.slice(0, 32)
  return RESERVED_USERNAMES.has(name) ? `${name}-1` : name
}

export function checkUsername(value: string): string {
  const name = String(value ?? '').trim().toLowerCase()
  if (!USERNAME_PATTERN.test(name)) {
    throw new ValidationError('A username is lowercase letters, digits, "_", "." and "-", starts with a letter or "_", and has at most 32 characters', 'invalid_username')
  }
  if (RESERVED_USERNAMES.has(name)) throw new ValidationError('This name belongs to a system account', 'reserved_username')
  return name
}

/**
 * The user's SSH username. Set on first use: their email's local part, with a number added when
 * someone else already has it, so no two people ever share a login.
 */
export async function ensureUsername(db: Executor, user: { id: string; email: string; username: string | null }): Promise<string> {
  if (user.username) return user.username
  const base = deriveUsername(user.email)
  for (let attempt = 0; attempt < 50; attempt++) {
    const suffix = attempt === 0 ? '' : String(attempt + 1)
    const candidate = `${base.slice(0, 32 - suffix.length)}${suffix}`
    try {
      // A savepoint, so a clash does not abort the caller's transaction.
      const [row] = await db.transaction((sp) =>
        sp
          .update(schema.users)
          .set({ username: candidate })
          .where(and(eq(schema.users.id, user.id), sql`${schema.users.username} is null`))
          .returning({ username: schema.users.username }),
      )
      if (row?.username) return row.username
      // Someone set it meanwhile.
      const [now] = await db.select({ username: schema.users.username }).from(schema.users).where(eq(schema.users.id, user.id))
      if (now?.username) return now.username
      throw new NotFoundError('User not found')
    } catch (error) {
      if (!isUniqueViolation(error, 'users_username_lower_idx')) throw error
    }
  }
  throw new ConflictError('No free username could be found', 'username_taken')
}

/** Set a user's username (admins). Unique whatever the case. */
export async function setUsername(db: Executor, user_id: string, value: string): Promise<string> {
  const name = checkUsername(value)
  try {
    const [row] = await db.transaction((sp) =>
      sp.update(schema.users).set({ username: name }).where(eq(schema.users.id, user_id)).returning({ username: schema.users.username }),
    )
    if (!row) throw new NotFoundError('User not found')
    return row.username!
  } catch (error) {
    if (isUniqueViolation(error, 'users_username_lower_idx')) throw new ConflictError('Another person already has this username', 'username_taken')
    throw error
  }
}

