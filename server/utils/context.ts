import type { Context } from '@certifly/core/context'
import { queueEventAlerts } from '@certifly/core/alerts'
import { createMailer } from '@certifly/core/mailer'
import { db } from 'hub:db'

let context: Context | undefined

/**
 * Process-wide domain context. `db` is NuxtHub's Drizzle client. Its type comes from the
 * schema NuxtHub bundles from packages/db, which structurally equals core's `Database`
 * (Postgres Drizzle over the same tables), so no cast is needed; the typecheck guards that.
 */
export function useContext(): Context {
  if (context) return context
  const config = env()
  context = {
    db,
    mailer: createMailer(config),
    base_url: config.URL,
    // Alert rules react to stored (and committed) audit events through a job.
    emit: (event) => queueEventAlerts(context!, event),
    enqueue: enqueueJob,
    secret_key: config.SECRET_KEY,
    setup_token: config.SETUP_TOKEN,
    keys: deferredKeyProvider(),
    pki_base_url: (config.PKI_BASE_URL ?? config.URL).replace(/\/+$/, ''),
    acme: { http01_port: config.ACME_HTTP01_PORT, tlsalpn01_port: config.ACME_TLSALPN01_PORT },
  }
  return context
}
