import { randomUUID } from 'node:crypto'
import { schema } from '@certifly/db'
import { and, desc, eq, gt, isNull, lt, sql } from 'drizzle-orm'
import type { Context } from '../context'
import { emailCodeHash, randomCode, randomToken, safeEqualHex, sha256 } from '../crypto'
import { AuthenticationError, AuthorizationError, ValidationError } from '../errors'
import { signInMail } from '../mail-templates'

export const EMAIL_TOKEN_TTL_MS = 15 * 60 * 1000
export const MAX_CODE_ATTEMPTS = 5

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export type EmailToken = typeof schema.emailTokens.$inferSelect
export type EmailTokenMeta = EmailToken['meta']

/** Lowercased, trimmed email address; throws for anything that is not one. */
export function normalizeEmail(input: string): string {
  const email = input.trim().toLowerCase()
  if (!EMAIL_PATTERN.test(email)) throw new ValidationError('Enter a valid email address')
  return email
}

/** Throws unless this instance can send mail; without it, codes and links would reach nobody. */
export function assertEmailEnabled(ctx: Context) {
  if (!ctx.mailer.delivers) throw new AuthorizationError('Signing in by email is not available on this instance', 'email_disabled')
}

/** Email a one-time link and code. `meta` is carried through to verification. */
export async function issueEmailToken(ctx: Context, input: { email: string; meta?: EmailTokenMeta; purpose?: 'sign_in' | 'reauth' }) {
  assertEmailEnabled(ctx)
  const id = randomUUID()
  const token = randomToken()
  const code = randomCode()
  await ctx.db.insert(schema.emailTokens).values({
    id,
    email: input.email,
    token_hash: sha256(token),
    code_hash: emailCodeHash(ctx.secret_key, id, code),
    meta: input.meta ?? {},
    expires_at: new Date(Date.now() + EMAIL_TOKEN_TTL_MS),
  })
  const link = new URL('/signin/email', ctx.base_url)
  link.searchParams.set('token', token)
  await ctx.mailer.send({ to: input.email, ...signInMail({ code, link: link.toString(), purpose: input.purpose }) })
}

/** Consume a link token. */
export async function consumeLinkToken(ctx: Context, token: string): Promise<EmailToken> {
  assertEmailEnabled(ctx)
  const [record] = await ctx.db
    .update(schema.emailTokens)
    .set({ consumed_at: new Date() })
    .where(
      and(
        eq(schema.emailTokens.token_hash, sha256(token)),
        isNull(schema.emailTokens.consumed_at),
        gt(schema.emailTokens.expires_at, new Date()),
      ),
    )
    .returning()
  if (!record) throw new AuthenticationError('This sign-in link is invalid or has expired', 'invalid_token')
  return record
}

/**
 * Consume the latest pending token for an email by its code. Each guess counts against that
 * token, which is burned after too many.
 */
export async function consumeCode(ctx: Context, input: { email: string; code: string }): Promise<EmailToken> {
  assertEmailEnabled(ctx)
  const email = input.email.trim().toLowerCase()
  const invalid = () => new AuthenticationError('This code is invalid or has expired', 'invalid_code')
  const [record] = await ctx.db
    .select({ id: schema.emailTokens.id })
    .from(schema.emailTokens)
    .where(
      and(
        eq(schema.emailTokens.email, email),
        isNull(schema.emailTokens.consumed_at),
        gt(schema.emailTokens.expires_at, new Date()),
      ),
    )
    .orderBy(desc(schema.emailTokens.created_at))
    .limit(1)
  if (!record) throw invalid()
  return checkCode(ctx, record.id, input.code, invalid)
}

/**
 * Check a code against a token. Each guess first claims one of the token's attempts in a
 * single update, so parallel guesses cannot get past the limit, and only a claimed attempt
 * is compared. A wrong guess that uses up the last attempt burns the token, link included.
 * Consuming and burning only ever set `consumed_at`, never clear it, so a guess that lands
 * after the token was used cannot bring it back.
 */
export async function checkCode(ctx: Context, tokenId: string, code: string, invalid: () => Error): Promise<EmailToken> {
  const tokens = schema.emailTokens
  const [claimed] = await ctx.db
    .update(tokens)
    .set({ attempts: sql`${tokens.attempts} + 1` })
    .where(and(eq(tokens.id, tokenId), isNull(tokens.consumed_at), gt(tokens.expires_at, sql`now()`), lt(tokens.attempts, MAX_CODE_ATTEMPTS)))
    .returning({ code_hash: tokens.code_hash, attempts: tokens.attempts })
  if (!claimed) throw invalid()

  if (!safeEqualHex(claimed.code_hash, emailCodeHash(ctx.secret_key, tokenId, code.trim()))) {
    if (claimed.attempts >= MAX_CODE_ATTEMPTS) {
      await ctx.db
        .update(tokens)
        .set({ consumed_at: sql`coalesce(${tokens.consumed_at}, now())` })
        .where(eq(tokens.id, tokenId))
    }
    throw invalid()
  }

  const [consumed] = await ctx.db
    .update(tokens)
    .set({ consumed_at: new Date() })
    .where(and(eq(tokens.id, tokenId), isNull(tokens.consumed_at)))
    .returning()
  if (!consumed) throw invalid()
  return consumed
}
