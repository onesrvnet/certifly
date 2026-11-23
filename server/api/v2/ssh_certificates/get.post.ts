import { z } from 'zod'
import { getSshCertificate } from '@certifly/core/ssh-certificates'
import { presentSshCertificate } from '@certifly/core/ssh-presenters'

/** Get an SSH certificate, including the certificate line. Operators and admins see all; everyone else only their own user certificates. */
export default defineRpc(z.object({ id: z.uuid() }), async (event, body) => {
  const { actor } = await requireAuth(event)
  return { data: presentSshCertificate(actor, await getSshCertificate(useContext(), actor, body.id)) }
})
