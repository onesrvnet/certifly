import { z } from 'zod'
import { getSshCertificate, revokeSshCertificate } from '@certifly/core/ssh-certificates'
import { presentSshCertificate } from '@certifly/core/ssh-presenters'

/**
 * Revoke an SSH certificate
 *
 * Puts the certificate on its CA's revocation list, which is rebuilt right away. `reason` is
 * one of unspecified (default), key_compromise, ca_compromise, affiliation_changed,
 * superseded, cessation_of_operation, privilege_withdrawn. Revoking a revoked certificate
 * changes nothing; an expired one cannot be revoked (`certificate_not_revocable`). People revoke
 * their own user certificates; operators and admins revoke any, also with API keys.
 */
export default defineRpc(z.object({ id: z.uuid(), reason: z.string().max(40).optional() }), async (event, { id, ...body }) => {
  const { actor } = await requireAuth(event)
  const ctx = useContext()
  await revokeSshCertificate(ctx, actor, id, body)
  return { data: presentSshCertificate(actor, await getSshCertificate(ctx, actor, id)) }
})
