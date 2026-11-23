import { schema } from '@certifly/db'
import { revocationReasonCode, type RevocationReason } from '@certifly/pki'
import { eq } from 'drizzle-orm'
import { recordEvent, withTransaction } from './audit'
import { type ProtocolRequester, requestEvent } from './certificates'
import type { Context } from './context'
import { ConflictError, NotFoundError, ValidationError } from './errors'
import { type Actor, authorize, certificatePolicy } from './policies'

/**
 * RFC 5280 §5.3.1 reasons a leaf certificate may be revoked for. certificateHold is left out:
 * certifly has no way to release a hold, so it would be a permanent revocation under a
 * misleading name. aACompromise is about attribute authorities, which certifly does not run.
 */
export const LEAF_REVOCATION_REASONS = [
  'unspecified',
  'key_compromise',
  'ca_compromise',
  'affiliation_changed',
  'superseded',
  'cessation_of_operation',
  'privilege_withdrawn',
] as const satisfies readonly RevocationReason[]

/** RFC 5280 §5.3.1 reasons a CA may be revoked (or marked compromised) for. */
export const CA_REVOCATION_REASONS = [
  'unspecified',
  'key_compromise',
  'ca_compromise',
  'affiliation_changed',
  'superseded',
  'cessation_of_operation',
] as const satisfies readonly RevocationReason[]

export type LeafRevocationReason = (typeof LEAF_REVOCATION_REASONS)[number]
export type CaRevocationReason = (typeof CA_REVOCATION_REASONS)[number]

export function checkRevocationReason<R extends string>(allowed: readonly R[], reason: string): R {
  if (!allowed.includes(reason as R)) throw new ValidationError(`The revocation reason must be one of ${allowed.join(', ')}`, 'invalid_revocation_reason')
  return reason as R
}

export interface RevokeCertificateInput {
  reason: LeafRevocationReason
}

type CertificateRow = typeof schema.certificates.$inferSelect

/**
 * Revoke a leaf certificate with an RFC 5280 reason. It goes on the CRL of the CA key that
 * signed it, which a job rebuilds right away, and stays there until it expires. Superseded
 * certificates can be revoked too (their key may be what leaked). Revoking a revoked certificate
 * changes nothing; expired and imported ones cannot be revoked (an imported one is revoked by its
 * own issuer). Operators and admins, also with API keys, so automation and emergencies work.
 */
export async function revokeCertificate(ctx: Context, actor: Actor, id: string, input: RevokeCertificateInput): Promise<CertificateRow> {
  authorize(certificatePolicy, actor, 'revoke', undefined)
  return revoke(ctx, actor, id, input)
}

/**
 * Revoke for a protocol client (ACME revokeCert) that has proven it may: it holds the account
 * that ordered the certificate, or the certificate's own key. The caller has done that check.
 */
export function revokeCertificateAs(ctx: Context, requester: ProtocolRequester, id: string, input: RevokeCertificateInput): Promise<CertificateRow> {
  return revoke(ctx, requester, id, input)
}

async function revoke(ctx: Context, actor: Actor | ProtocolRequester, id: string, input: RevokeCertificateInput): Promise<CertificateRow> {
  const reason = checkRevocationReason(LEAF_REVOCATION_REASONS, input.reason)
  const c = schema.certificates
  const result = await withTransaction(ctx, async (tx) => {
    const [row] = await tx.select().from(c).where(eq(c.id, id)).for('update')
    if (!row) throw new NotFoundError('Certificate not found')
    if (row.source === 'import' || !row.ca_id) {
      throw new ConflictError('This certificate was issued elsewhere; revoke it with its issuer', 'certificate_not_revocable')
    }
    if (row.revoked_at) return { row, changed: false }
    const now = new Date()
    if (row.not_after.getTime() <= now.getTime()) throw new ConflictError('The certificate has expired; there is nothing left to revoke', 'certificate_not_revocable')
    const [updated] = await tx
      .update(c)
      .set({ status: 'revoked', revoked_at: now, revocation_reason: revocationReasonCode(reason) })
      .where(eq(c.id, id))
      .returning()
    await recordEvent(
      ctx,
      requestEvent(actor, 'certificates.revoke', { type: 'certificate', id }, {
        ca_id: row.ca_id,
        template_id: row.template_id,
        serial: row.serial,
        reason,
        previous_status: row.status,
      }),
      tx,
    )
    return { row: updated!, changed: true }
  })
  // After the commit, so the job sees the revocation.
  if (result.changed) ctx.enqueue({ name: 'crls.rebuild', data: { ca_id: result.row.ca_id! } })
  return result.row
}
