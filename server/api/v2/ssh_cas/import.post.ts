import { z } from 'zod'
import { importSshCa } from '@certifly/core/ssh-cas'
import { presentSshCa } from '@certifly/core/ssh-presenters'

/**
 * Import an SSH certificate authority
 *
 * Stores an existing CA key. `private_key` is an unencrypted OpenSSH or PKCS#8 private key as
 * text; a passphrase-protected one is refused with `ssh_key_encrypted` (remove the passphrase
 * first, for example with `ssh-keygen -p -N ""`). The key is encrypted at rest and can never be
 * read back. Ed25519, ECDSA P-256 and P-384, and RSA of 2048 bits and more are accepted.
 * Admins only, from a recently re-authenticated session; API keys are refused.
 */
export default defineRpc(
  z.object({
    name: z.string().max(200),
    slug: z.string().max(100),
    description: z.string().max(1000).optional(),
    private_key: z.string().min(1).max(32_768),
  }),
  async (event, body) => {
    const { actor } = await requireAuth(event)
    return { data: presentSshCa(actor, await importSshCa(useContext(), actor, body)) }
  },
)
