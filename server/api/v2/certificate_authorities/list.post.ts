import { z } from 'zod'
import { listCertificateAuthorities } from '@certifly/core/cas'
import { presentCertificateAuthority } from '@certifly/core/presenters'

/**
 * List certificate authorities
 *
 * Every CA as a flat list, alphabetically, each with its `parent_ca_id`, so the client can build
 * the hierarchy. Externally signed CAs carry the subjects of their imported chain
 * (`chain_subjects`, issuer first, root last). Every signed-in role may list. Pass `next_cursor`
 * back as `cursor` for the next page.
 */
export default defineRpc(z.object({ ...paginationSchema }), async (event, body) => {
  const { actor } = await requireAuth(event)
  const { rows, next_cursor } = await listCertificateAuthorities(useContext(), actor, body)
  return { data: rows.map((row) => presentCertificateAuthority(actor, row)), next_cursor }
})
