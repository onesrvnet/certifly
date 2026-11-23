import { z } from 'zod'
import { importCertificates } from '@certifly/core/inventory'
import { presentImportResult } from '@certifly/core/presenters'

/**
 * Import certificates
 *
 * Adds certificates issued elsewhere to the inventory, from `pem`: one certificate or several
 * (a full-chain file, say). Each is stored with `source: "import"`, no CA and the issuer's DN, so
 * it shows in the list, on the dashboard and in expiry alerts; it cannot be revoked or renewed
 * here. Certificates certifly already has (same SHA-256 fingerprint) and CA certificates are
 * skipped and listed in `skipped` with a `reason`. `tag_ids` tags every imported certificate. Operators and admins, also with API keys.
 */
export default defineRpc(z.object({ pem: z.string().min(1).max(1_000_000), notes: z.string().max(2000).optional(), tag_ids: tagIdsSchema.optional() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentImportResult(actor, await importCertificates(useContext(), actor, body)) }
})
