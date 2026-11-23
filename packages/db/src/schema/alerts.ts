import { boolean, index, integer, jsonb, pgEnum, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core'
import { id, timestamps } from './columns'

export const alertChannelKind = pgEnum('alert_channel_kind', ['email', 'webhook'])
export const alertEvent = pgEnum('alert_event', ['expiring', 'issued', 'revoked', 'ca_expiring', 'crl_failed', 'ssh_host_expiring'])
export const alertDeliveryStatus = pgEnum('alert_delivery_status', ['pending', 'sent', 'retrying', 'failed'])

/**
 * Where an alert goes. Email: a list of recipients. Webhook: a URL and the HMAC secret, which is
 * encrypted with the server's SECRET_KEY (`secret_enc`) and shown to the admin only once.
 */
export type AlertChannelConfig = { recipients: string[] } | { url: string; secret_enc: string }

export const alertChannels = pgTable('alert_channels', {
  id: id(),
  name: text().notNull(),
  kind: alertChannelKind().notNull(),
  config: jsonb().$type<AlertChannelConfig>().notNull(),
  ...timestamps,
})

/** Which certificates or CAs a rule covers. Empty id lists mean all. */
export interface AlertRuleFilter {
  ca_ids: string[]
  template_ids: string[]
  /** Certificates imported into the inventory; they have no CA or template in certifly. */
  include_imported: boolean
}

/** When to alert, about what, and through which channels. */
export const alertRules = pgTable('alert_rules', {
  id: id(),
  name: text().notNull(),
  event: alertEvent().notNull(),
  filter: jsonb().$type<AlertRuleFilter>().notNull(),
  /** Warning thresholds for the expiry events, in days before notAfter. Empty for the others. */
  days_before: integer().array().notNull().default([]),
  channel_ids: uuid().array().notNull(),
  enabled: boolean().notNull().default(true),
  ...timestamps,
})

/**
 * One alert to one channel. The dedupe key names the rule, channel, subject and threshold, so a
 * certificate gets each warning once however often the scan runs. Rules and channels may be
 * deleted later; the history stays.
 */
export const alertDeliveries = pgTable(
  'alert_deliveries',
  {
    id: id(),
    rule_id: uuid().references(() => alertRules.id, { onDelete: 'set null' }),
    channel_id: uuid().references(() => alertChannels.id, { onDelete: 'set null' }),
    /** Null for a test sent from the channel's page, which no rule caused. */
    event: alertEvent(),
    test: boolean().notNull().default(false),
    subject_type: text(),
    subject_id: uuid(),
    dedupe_key: text().notNull().unique(),
    status: alertDeliveryStatus().notNull().default('pending'),
    attempts: integer().notNull().default(0),
    last_error: text(),
    /** What is sent: ids and facts about the subject, never secrets. */
    payload: jsonb().$type<Record<string, unknown>>().notNull(),
    last_attempt_at: timestamp({ withTimezone: true }),
    sent_at: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [
    index('alert_deliveries_created_idx').on(t.created_at, t.id),
    index('alert_deliveries_rule_idx').on(t.rule_id),
    index('alert_deliveries_channel_idx').on(t.channel_id),
  ],
)
