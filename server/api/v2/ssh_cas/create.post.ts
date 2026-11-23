import { z } from 'zod'
import { createSshCa } from '@certifly/core/ssh-cas'
import { presentSshCa } from '@certifly/core/ssh-presenters'

/**
 * Create an SSH certificate authority
 *
 * Generates a new key inside certifly (`ed25519` by default, or `ecdsa-p256` or `rsa-4096`).
 * One key signs both user and host certificates. The slug (lowercase letters, digits and
 * hyphens) is part of the public URLs and cannot change (`slug_taken`). The private key never
 * leaves certifly. Admins only, from a recently re-authenticated session (`reauth_required`);
 * API keys are refused.
 */
export default defineRpc(
  z.object({
    name: z.string().max(200),
    slug: z.string().max(100),
    description: z.string().max(1000).optional(),
    key_algorithm: z.enum(['ed25519', 'ecdsa-p256', 'rsa-4096']).optional(),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    return { data: presentSshCa(actor, await createSshCa(useContext(), actor, body)) }
  },
)
