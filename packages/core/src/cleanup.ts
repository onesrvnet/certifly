import { schema } from '@certifly/db'
import { and, isNotNull, lt, or } from 'drizzle-orm'
import { deleteExpiredAcmeNonces, deleteExpiredAcmeOrders } from './acme'
import { SESSION_IDLE_MS } from './auth/sessions'
import type { Context } from './context'
import { MAX_WINDOW_SEC } from './rate-limit'

const DAY_MS = 24 * 60 * 60 * 1000

/** How long unused or expired records are kept before they are deleted. */
export const RETENTION = {
  /** Used or expired email sign-in tokens. */
  shortLivedMs: DAY_MS,
  /** Expired or accepted invites, kept a while so the invites list still shows what happened. */
  inviteMs: 30 * DAY_MS,
  /** ACME orders that ran out or were finished, with their authorizations and challenges. */
  acmeOrderMs: 30 * DAY_MS,
}

/** Delete expired sign-in tokens, sessions, rate-limit windows, old invites and spent ACME nonces and orders. Safe to run repeatedly. */
export async function cleanupExpired(ctx: Context, now = new Date()) {
  const ago = (ms: number) => new Date(now.getTime() - ms)

  const emailTokens = await ctx.db
    .delete(schema.emailTokens)
    .where(
      or(
        lt(schema.emailTokens.expires_at, ago(RETENTION.shortLivedMs)),
        and(isNotNull(schema.emailTokens.consumed_at), lt(schema.emailTokens.consumed_at, ago(RETENTION.shortLivedMs))),
      ),
    )
    .returning({ id: schema.emailTokens.id })

  const sessions = await ctx.db
    .delete(schema.sessions)
    .where(or(lt(schema.sessions.expires_at, now), lt(schema.sessions.last_active_at, ago(SESSION_IDLE_MS))))
    .returning({ id: schema.sessions.id })

  // A window is over once its start is further back than the longest window allowed.
  const rateLimits = await ctx.db
    .delete(schema.rateLimits)
    .where(lt(schema.rateLimits.window_start, new Date(now.getTime() - MAX_WINDOW_SEC * 1000)))
    .returning({ key: schema.rateLimits.key })

  const invites = await ctx.db
    .delete(schema.invites)
    .where(
      or(
        lt(schema.invites.expires_at, ago(RETENTION.inviteMs)),
        and(isNotNull(schema.invites.accepted_at), lt(schema.invites.accepted_at, ago(RETENTION.inviteMs))),
      ),
    )
    .returning({ id: schema.invites.id })

  const cliLogins = await ctx.db.delete(schema.cliLogins).where(lt(schema.cliLogins.expires_at, ago(RETENTION.shortLivedMs))).returning({ id: schema.cliLogins.id })
  const cliSessions = await ctx.db
    .delete(schema.cliSessions)
    .where(or(lt(schema.cliSessions.expires_at, ago(RETENTION.shortLivedMs)), and(isNotNull(schema.cliSessions.revoked_at), lt(schema.cliSessions.revoked_at, ago(RETENTION.shortLivedMs)))))
    .returning({ id: schema.cliSessions.id })
  const hostChallenges = await ctx.db.delete(schema.sshHostChallenges).where(lt(schema.sshHostChallenges.expires_at, ago(RETENTION.shortLivedMs))).returning({ id: schema.sshHostChallenges.id })
  const joinTokens = await ctx.db.delete(schema.sshJoinTokens).where(lt(schema.sshJoinTokens.expires_at, ago(RETENTION.inviteMs))).returning({ id: schema.sshJoinTokens.id })

  const acmeNonces = await deleteExpiredAcmeNonces(ctx, now)
  const acmeOrders = await deleteExpiredAcmeOrders(ctx, ago(RETENTION.acmeOrderMs))

  return {
    email_tokens: emailTokens.length,
    sessions: sessions.length,
    rate_limits: rateLimits.length,
    invites: invites.length,
    cli_logins: cliLogins.length,
    cli_sessions: cliSessions.length,
    ssh_host_challenges: hostChallenges.length,
    ssh_join_tokens: joinTokens.length,
    acme_nonces: acmeNonces,
    acme_orders: acmeOrders,
  }
}
