import { z } from 'zod'
import { dashboardOverview } from '@certifly/core/dashboard'

/**
 * Get the dashboard
 *
 * The certificate numbers, what needs attention (certificates expiring within 30 days, CAs
 * expiring within a year, late CRLs and, for operators and admins, failed alert deliveries of
 * the last 7 days), active certificates expiring per week for the next 13 weeks, certificates
 * issued per week for the last 8 weeks (oldest first) and each CA's health. Every signed-in role
 * may read.
 */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: { id: 'dashboard', ...(await dashboardOverview(useContext(), actor)) } }
})
