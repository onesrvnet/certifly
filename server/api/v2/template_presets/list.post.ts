import { z } from 'zod'
import { listTemplatePresets } from '@certifly/core/templates'

/**
 * List template presets
 *
 * The built-in starting points for templates (`webserver_tls`, `mtls_server`, `mtls_client`,
 * `server_client`) with every setting they fill in, as `templates.create` takes them. Every
 * signed-in role may list.
 */
export default defineRpc(z.object({}), async (event) => {
  const { actor } = await requireAuth(event)
  return { data: listTemplatePresets(actor) }
})
