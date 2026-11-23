import { schema } from '@certifly/db'
import {
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { and, asc, eq } from 'drizzle-orm'
import { eventFor, recordEvent } from '../audit'
import type { Context } from '../context'
import { AuthenticationError, ConflictError, isUniqueViolation, NotFoundError, ValidationError } from '../errors'
import type { Actor } from '../policies'
import { presentPasskey } from '../presenters'
import type { User } from './provision'
import { assertStepUp } from './sessions'

/**
 * Passkeys (WebAuthn). The relying party is the instance's base host. Challenges are
 * kept by the caller (a short-lived cookie) between the two steps of each flow.
 */

/** What the browser sends back from navigator.credentials.create / get (JSON form). */
export type { AuthenticationResponseJSON, RegistrationResponseJSON }

function relyingParty(ctx: Context) {
  return { rpID: new URL(ctx.base_url).hostname, rpName: 'certifly' }
}

const transportsOf = (value: string[]) => value as AuthenticatorTransport[]

/**
 * Options for adding a passkey to the actor's account. Adding a way to sign in needs a recent
 * re-authentication; asking here already lets the browser prompt wait until that is done.
 */
export async function passkeyRegistrationOptions(ctx: Context, actor: Actor) {
  assertStepUp(actor)
  const [user] = await ctx.db.select().from(schema.users).where(eq(schema.users.id, actor.id))
  const existing = await ctx.db
    .select({ credential_id: schema.passkeys.credential_id, transports: schema.passkeys.transports })
    .from(schema.passkeys)
    .where(eq(schema.passkeys.user_id, actor.id))
  return generateRegistrationOptions({
    ...relyingParty(ctx),
    userName: user!.email,
    userDisplayName: user!.name,
    userID: new TextEncoder().encode(user!.id),
    attestationType: 'none',
    excludeCredentials: existing.map((p) => ({ id: p.credential_id, transports: transportsOf(p.transports) })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  })
}

/** Verify the browser's response and store the new passkey. Needs a recent re-authentication. */
export async function registerPasskey(
  ctx: Context,
  actor: Actor,
  input: { response: RegistrationResponseJSON; challenge: string; origin: string; name?: string },
) {
  assertStepUp(actor)
  const result = await verifyRegistrationResponse({
    response: input.response,
    expectedChallenge: input.challenge,
    expectedOrigin: input.origin,
    expectedRPID: relyingParty(ctx).rpID,
    requireUserVerification: false,
  }).catch(() => {
    // The library's reason is for developers, not for the person adding the passkey.
    throw new ValidationError('The passkey could not be verified', 'passkey_invalid')
  })
  if (!result.verified) throw new ValidationError('The passkey could not be verified', 'passkey_invalid')
  const { credential } = result.registrationInfo
  const [passkey] = await ctx.db
    .insert(schema.passkeys)
    .values({
      user_id: actor.id,
      credential_id: credential.id,
      public_key: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports ?? [],
      name: input.name?.trim() || 'Passkey',
    })
    .returning()
    .catch((error) => {
      if (isUniqueViolation(error)) throw new ConflictError('This passkey is already registered', 'passkey_exists')
      throw error
    })
  await recordEvent(ctx, eventFor(actor, 'passkeys.create', { type: 'passkey', id: passkey!.id }))
  return presentPasskey(passkey!)
}

/** Options for signing in with any passkey of this site (no email needed). */
export function passkeyAuthenticationOptions(ctx: Context) {
  return generateAuthenticationOptions({ rpID: relyingParty(ctx).rpID, userVerification: 'preferred' })
}

/** Verify a passkey sign-in and return the passkey's owner. Deactivated users are refused. */
export async function authenticatePasskey(
  ctx: Context,
  input: { response: AuthenticationResponseJSON; challenge: string; origin: string },
): Promise<{ user: User }> {
  const invalid = () => new AuthenticationError('This passkey cannot be used to sign in', 'passkey_invalid')
  const [row] = await ctx.db
    .select({ passkey: schema.passkeys, owner: schema.users })
    .from(schema.passkeys)
    .innerJoin(schema.users, eq(schema.users.id, schema.passkeys.user_id))
    .where(eq(schema.passkeys.credential_id, input.response.id))
  if (!row) throw invalid()

  const result = await verifyAuthenticationResponse({
    response: input.response,
    expectedChallenge: input.challenge,
    expectedOrigin: input.origin,
    expectedRPID: relyingParty(ctx).rpID,
    credential: {
      id: row.passkey.credential_id,
      // A copy backed by a plain ArrayBuffer, as the library expects.
      publicKey: new Uint8Array(row.passkey.public_key),
      counter: row.passkey.counter,
      transports: transportsOf(row.passkey.transports),
    },
    requireUserVerification: false,
  }).catch(() => {
    throw invalid()
  })
  if (!result.verified) throw invalid()
  await ctx.db
    .update(schema.passkeys)
    .set({ counter: result.authenticationInfo.newCounter, last_used_at: new Date() })
    .where(eq(schema.passkeys.id, row.passkey.id))

  if (row.owner.deleted_at) throw invalid()
  return { user: row.owner }
}

export async function listPasskeys(ctx: Context, actor: Actor) {
  const rows = await ctx.db
    .select()
    .from(schema.passkeys)
    .where(eq(schema.passkeys.user_id, actor.id))
    .orderBy(asc(schema.passkeys.created_at))
  return rows.map(presentPasskey)
}

async function ownPasskey(ctx: Context, actor: Actor, id: string) {
  const [passkey] = await ctx.db
    .select()
    .from(schema.passkeys)
    .where(and(eq(schema.passkeys.id, id), eq(schema.passkeys.user_id, actor.id)))
  if (!passkey) throw new NotFoundError('Passkey not found')
  return passkey
}

export async function renamePasskey(ctx: Context, actor: Actor, id: string, name: string) {
  const passkey = await ownPasskey(ctx, actor, id)
  if (!name.trim()) throw new ValidationError('Name cannot be empty')
  const [updated] = await ctx.db
    .update(schema.passkeys)
    .set({ name: name.trim() })
    .where(eq(schema.passkeys.id, passkey.id))
    .returning()
  return presentPasskey(updated!)
}

/** Remove one of the actor's passkeys. Needs a recent re-authentication. */
export async function deletePasskey(ctx: Context, actor: Actor, id: string) {
  const passkey = await ownPasskey(ctx, actor, id)
  assertStepUp(actor)
  await ctx.db.delete(schema.passkeys).where(eq(schema.passkeys.id, passkey.id))
  await recordEvent(ctx, eventFor(actor, 'passkeys.delete', { type: 'passkey', id: passkey.id }))
}
