import { z } from 'zod'
import { certificateStats } from '@certifly/core/certificates'

/**
 * Get certificate statistics
 *
 * Counts for the dashboard: active certificates, those expiring within 7 and 30 days (imported
 * ones included), expired ones, those issued in the last 7 days, revoked certificates still on a
 * CRL, imported certificates expiring within 30 days, active CAs and revoked CAs. Every signed-in
 * role may read.
 */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: { id: 'certificate_stats', ...(await certificateStats(useContext(), actor)) } }
})
