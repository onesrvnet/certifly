import { z } from 'zod'

const keyAlgorithm = z.enum(['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'])
const subjectField = z.enum(['CN', 'O', 'OU', 'C', 'ST', 'L', 'E'])

/**
 * The settings of a template, all optional: `create` fills gaps from a preset, `update` keeps
 * what it is not given. Core validates the whole result.
 */
export const templateSettingsSchema = {
  allowed_san_types: z.array(z.enum(['dns', 'ip', 'email', 'uri'])).max(4).optional(),
  allowed_dns: z.array(z.string().trim().max(253)).max(100).optional(),
  allowed_ips: z.array(z.string().trim().max(64)).max(100).optional(),
  allow_wildcards: z.boolean().optional(),
  require_san: z.boolean().optional(),
  require_common_name: z.boolean().optional(),
  subject_defaults: z.partialRecord(subjectField, z.string().max(256)).optional(),
  allowed_subject_fields: z.array(subjectField).max(7).optional(),
  key_algorithms: z.array(keyAlgorithm).min(1).max(5).optional(),
  max_ttl_seconds: z.number().int().positive().optional(),
  default_ttl_seconds: z.number().int().positive().optional(),
  key_usages: z.array(z.enum(['digital_signature', 'non_repudiation', 'key_encipherment', 'data_encipherment', 'key_agreement'])).max(5).optional(),
  extended_key_usages: z.array(z.enum(['server_auth', 'client_auth', 'code_signing', 'email_protection', 'time_stamping', 'ocsp_signing'])).max(6).optional(),
  allow_server_keygen: z.boolean().optional(),
  allow_acme: z.boolean().optional(),
  allow_est: z.boolean().optional(),
  renew_before_days: z.number().int().min(0).max(365).optional(),
}

/** A generated key pair instead of a CSR; the private key comes back once. */
export const keygenSchema = z.object({
  algorithm: keyAlgorithm,
  format: z.enum(['pem', 'pkcs12']),
  pkcs12_password: z.string().max(1024).optional(),
})

/** Tag ids; core checks that each exists. */
export const tagIdsSchema = z.array(z.uuid()).max(50)

/** The filters `certificates.list` and `certificate_groups.list` share. */
export const certificateFilterSchema = {
  status: z.enum(['active', 'revoked', 'expired', 'superseded']).optional(),
  ca_id: z.uuid().optional(),
  template_id: z.uuid().optional(),
  source: z.enum(['ui', 'api', 'acme', 'est', 'import']).optional(),
  imported: z.boolean().optional(),
  expiring_before: z.iso.datetime({ offset: true }).optional(),
  query: z.string().max(253).optional(),
  tag_ids: tagIdsSchema.optional(),
  untagged: z.boolean().optional(),
}

export const sanSchema = z.object({ type: z.enum(['dns', 'ip', 'email', 'uri']), value: z.string().trim().min(1).max(2048) })

/** Issue and renew answers may hold a private key: no cache may keep them. */
export function noStore(event: import('h3').H3Event) {
  setResponseHeaders(event, { 'cache-control': 'no-store', pragma: 'no-cache' })
}

/** Where a request came from, as recorded on the certificate: the UI, or a script with an API key. */
export const requestSource = (apiKeyId: string | undefined) => (apiKeyId ? 'api' : 'ui') as 'api' | 'ui'
