import { z } from 'zod'
import { createAlertChannel } from '@certifly/core/alerts'
import { presentAlertChannelResult } from '@certifly/core/presenters'

/**
 * Create an alert channel
 *
 * `kind: "email"` with `recipients`, or `kind: "webhook"` with an http(s) `url`. A webhook gets a
 * new secret, returned once as `secret` and never again; every delivery is a JSON POST signed
 * with it in `X-Certifly-Signature: sha256=<hex HMAC-SHA256 of the raw body>`, with the attempt's
 * Unix time in `X-Certifly-Timestamp` and in the body's `timestamp`. Redirects are not followed
 * and receivers have 10 seconds to answer. Sent with `Cache-Control: no-store`. Admins only, from
 * a recently re-authenticated session.
 */
export default defineRpc(
  z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('email'), name: z.string().max(100), recipients: z.array(z.string().max(254)).min(1).max(20) }),
    z.object({ kind: z.literal('webhook'), name: z.string().max(100), url: z.string().max(2048) }),
  ]),
  async (event, body) => {
    noStore(event)
    const { actor } = await requireAuth(event)
    return { data: presentAlertChannelResult(actor, await createAlertChannel(useContext(), actor, body)) }
  },
)
