import { schema, type LeafKeyUsage } from '@certifly/db'
import { inspectCertificate, parseCertificateBundle, PkiError, type CertificateInfo } from '@certifly/pki'
import { inArray } from 'drizzle-orm'
import { eventFor, recordEvent, withTransaction } from './audit'
import type { Context } from './context'
import { isUniqueViolation, ValidationError } from './errors'
import { type Actor, authorize, certificatePolicy } from './policies'
import { checkTagIds, replaceTags } from './tags'

type CertificateRow = typeof schema.certificates.$inferSelect

/** A paste or file of this many certificates is plenty; more is a mistake or abuse. */
export const MAX_IMPORT_CERTIFICATES = 100

const LEAF_KEY_USAGES: readonly string[] = ['digital_signature', 'non_repudiation', 'key_encipherment', 'data_encipherment', 'key_agreement'] satisfies LeafKeyUsage[]

export interface ImportCertificatesInput {
  /** One or more PEM certificates, e.g. a server's full chain file. */
  pem: string
  notes?: string
  /** Tags for every imported certificate. */
  tag_ids?: string[]
}

export interface SkippedCertificate {
  fingerprint_sha256: string
  subject: string
  /** `duplicate`: certifly already has it; `ca_certificate`: a CA, not a leaf (e.g. the chain of a full-chain file). */
  reason: 'duplicate' | 'ca_certificate'
  /** The certificate already stored, for duplicates. */
  certificate_id?: string
}

export interface ImportCertificatesResult {
  imported: CertificateRow[]
  skipped: SkippedCertificate[]
}

/** The row for a certificate issued elsewhere: no CA or template here, the issuer's DN only. */
function inventoryRow(info: CertificateInfo, actor: Actor, notes: string): typeof schema.certificates.$inferInsert {
  return {
    ca_id: null,
    ca_cert_id: null,
    template_id: null,
    source: 'import',
    status: 'active',
    serial: info.serial,
    subject_dn: info.subject,
    issuer_dn: info.issuer,
    common_name: info.subject.match(/(?:^|,\s*)CN=([^,]+)/)?.[1] ?? null,
    sans: info.sans,
    key_algorithm: info.public_key?.key_algorithm ?? 'unknown',
    // Only the usages certifly names; the DER keeps the rest and the detail page decodes it.
    key_usages: info.key_usages.filter((usage) => LEAF_KEY_USAGES.includes(usage)) as LeafKeyUsage[],
    extended_key_usages: info.extended_key_usage_names,
    not_before: info.not_before,
    not_after: info.not_after,
    fingerprint_sha256: info.fingerprint_sha256,
    certificate_der: info.der,
    requested_by_user_id: actor.id,
    requested_by_api_key_id: actor.kind === 'api_key' ? (actor.api_key_id ?? null) : null,
    notes,
  }
}

/**
 * Import certificates issued elsewhere into the inventory, from PEM: one certificate or a
 * bundle. Each is parsed and stored with `source = import`, no CA and the issuer's DN, so it
 * shows in the list, counts on the dashboard and in expiry alerts. Certificates certifly already
 * has (by SHA-256 fingerprint) and CA certificates are skipped and reported. Imported
 * certificates cannot be revoked or renewed here. Operators and admins, also with API keys.
 */
export async function importCertificates(ctx: Context, actor: Actor, input: ImportCertificatesInput): Promise<ImportCertificatesResult> {
  authorize(certificatePolicy, actor, 'import', undefined)
  const notes = input.notes?.trim() ?? ''
  if (notes.length > 2000) throw new ValidationError('Notes may be at most 2000 characters')
  let ders: Uint8Array[]
  try {
    ders = parseCertificateBundle(input.pem)
  } catch (error) {
    if (error instanceof PkiError) throw new ValidationError(error.message, error.code)
    throw new ValidationError('The PEM holds something that is not a certificate', 'invalid_pem')
  }
  if (!ders.length) throw new ValidationError('No PEM certificate found', 'invalid_pem')
  const tag_ids = await checkTagIds(ctx.db, input.tag_ids ?? [])
  if (ders.length > MAX_IMPORT_CERTIFICATES) throw new ValidationError(`At most ${MAX_IMPORT_CERTIFICATES} certificates per import`, 'too_many_certificates')

  const infos: CertificateInfo[] = []
  for (const der of ders) {
    try {
      infos.push(await inspectCertificate(der))
    } catch (error) {
      throw new ValidationError(`A certificate could not be read: ${error instanceof PkiError ? error.message : 'invalid DER'}`, 'invalid_certificate')
    }
  }

  const skipped: SkippedCertificate[] = []
  const seen = new Set<string>()
  const candidates = infos.filter((info) => {
    if (info.is_ca) {
      skipped.push({ fingerprint_sha256: info.fingerprint_sha256, subject: info.subject, reason: 'ca_certificate' })
      return false
    }
    if (seen.has(info.fingerprint_sha256)) return false
    seen.add(info.fingerprint_sha256)
    return true
  })

  const imported = await withTransaction(ctx, async (tx) => {
    const c = schema.certificates
    const fingerprints = candidates.map((info) => info.fingerprint_sha256)
    const known = fingerprints.length ? await tx.select({ id: c.id, fingerprint_sha256: c.fingerprint_sha256 }).from(c).where(inArray(c.fingerprint_sha256, fingerprints)) : []
    const byFingerprint = new Map(known.map((row) => [row.fingerprint_sha256, row.id]))
    const rows: CertificateRow[] = []
    for (const info of candidates) {
      const existing = byFingerprint.get(info.fingerprint_sha256)
      if (existing) {
        skipped.push({ fingerprint_sha256: info.fingerprint_sha256, subject: info.subject, reason: 'duplicate', certificate_id: existing })
        continue
      }
      // Another import of the same certificate may commit first; that is a duplicate too.
      const [row] = await tx.insert(c).values(inventoryRow(info, actor, notes)).onConflictDoNothing({ target: c.fingerprint_sha256 }).returning()
      if (!row) {
        skipped.push({ fingerprint_sha256: info.fingerprint_sha256, subject: info.subject, reason: 'duplicate' })
        continue
      }
      rows.push(row)
      const tagged = tag_ids.length ? (await replaceTags(tx, schema.certificateTags, row.id, tag_ids)).added : []
      await recordEvent(
        ctx,
        eventFor(actor, 'certificates.import', { type: 'certificate', id: row.id }, {
          serial: row.serial,
          issuer_dn: row.issuer_dn,
          fingerprint_sha256: row.fingerprint_sha256,
          not_after: row.not_after.toISOString(),
          tag_ids: tagged,
        }),
        tx,
      )
    }
    return rows
  }).catch((error) => {
    if (isUniqueViolation(error)) throw new ValidationError('A certificate was imported at the same time; try again', 'conflict')
    throw error
  })
  return { imported, skipped }
}
