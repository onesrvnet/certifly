import type { InternalApi } from 'nitropack/types'

export type Role = 'admin' | 'operator' | 'viewer'
export type KeyAlgorithm = 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096'
export type DnAttributeType = 'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L' | 'E' | 'DC' | 'serialNumber'
export interface NameConstraintSetInput {
  dns: string[]
  ip: string[]
  email: string[]
}
export interface NameConstraintsInput {
  permitted: NameConstraintSetInput
  excluded: NameConstraintSetInput
}
interface CaCreateCommon {
  name: string
  slug: string
  description?: string
  subject: { type: DnAttributeType; value: string }[]
  key_algorithm?: KeyAlgorithm
  path_length: number | null
  name_constraints?: NameConstraintsInput | null
  crl_validity_hours?: number
  crl_overlap_hours?: number
}
export type AuditActorType = 'user' | 'api_key' | 'acme' | 'est' | 'system' | 'cli' | 'ssh_host'
/** What a template's EKUs amount to, for a short label: from the server, never sent back. */
export type TemplateUsageHint = 'server' | 'client' | 'server_client' | 'other'
export type TemplateStatus = 'active' | 'archived'
export type TemplatePresetId = 'webserver_tls' | 'mtls_server' | 'mtls_client' | 'server_client'
export type SanType = 'dns' | 'ip' | 'email' | 'uri'
export type SubjectField = 'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L' | 'E'
export type LeafKeyUsage = 'digital_signature' | 'non_repudiation' | 'key_encipherment' | 'data_encipherment' | 'key_agreement'
export type ExtendedKeyUsage = 'server_auth' | 'client_auth' | 'code_signing' | 'email_protection' | 'time_stamping' | 'ocsp_signing'
export type CertificateStatus = 'active' | 'revoked' | 'expired' | 'superseded'
export type CertificateSource = 'ui' | 'api' | 'acme' | 'est' | 'import'
export type LeafRevocationReason = 'unspecified' | 'key_compromise' | 'ca_compromise' | 'affiliation_changed' | 'superseded' | 'cessation_of_operation' | 'privilege_withdrawn'
export type CaRevocationReason = 'unspecified' | 'key_compromise' | 'ca_compromise' | 'affiliation_changed' | 'superseded' | 'cessation_of_operation'
export type AlertEventName = 'expiring' | 'issued' | 'revoked' | 'ca_expiring' | 'crl_failed' | 'ssh_host_expiring'
export type AlertDeliveryStatus = 'pending' | 'sent' | 'retrying' | 'failed'
export interface AlertRuleInput {
  name: string
  event: AlertEventName
  ca_ids?: string[]
  template_ids?: string[]
  include_imported?: boolean
  days_before?: number[]
  channel_ids: string[]
  enabled?: boolean
}
export interface SanInput {
  type: SanType
  value: string
}
export interface KeygenInput {
  algorithm: KeyAlgorithm
  format: 'pem' | 'pkcs12'
  pkcs12_password?: string
}
/** Everything a template decides, as `templates.create` and `templates.update` take it. */
export interface TemplateSettingsInput {
  allowed_san_types: SanType[]
  allowed_dns: string[]
  allowed_ips: string[]
  allow_wildcards: boolean
  require_san: boolean
  require_common_name: boolean
  subject_defaults: Partial<Record<SubjectField, string>>
  allowed_subject_fields: SubjectField[]
  key_algorithms: KeyAlgorithm[]
  max_ttl_seconds: number
  default_ttl_seconds: number
  key_usages: LeafKeyUsage[]
  extended_key_usages: ExtendedKeyUsage[]
  allow_server_keygen: boolean
  allow_acme: boolean
  allow_est: boolean
  renew_before_days: number
}

/** Request bodies of the API endpoints (`POST /api/v2/<resource>/<action>`). */
export type TraefikClientAuthType = 'RequireAndVerifyClientCert' | 'VerifyClientCertIfGiven'

/** The Traefik settings of a trust bundle; a null name means the default. */
export interface TrustBundleTraefikInput {
  traefik_enabled?: boolean
  traefik_client_auth?: boolean
  traefik_client_auth_type?: TraefikClientAuthType
  traefik_tls_option_name?: string | null
  traefik_servers_transport?: boolean
  traefik_servers_transport_name?: string | null
  traefik_require_token?: boolean
}

/** The settings of an SSH host group, as `ssh_host_groups.create` and `.update` take them. */
export interface SshHostGroupSettings {
  description?: string
  host_patterns?: string[]
  user_ttl_default_seconds?: number
  user_ttl_max_seconds?: number
  user_extensions?: string[]
  force_command?: string | null
  source_address?: string[]
  key_policy?: 'any' | 'sk' | 'sk_attested'
  host_ttl_seconds?: number
}

export interface RpcInput {
  'auth_config.get': Record<string, never>
  'sign_in_codes.create': { email: string; setup_token?: string }
  'sign_in_codes.verify': { token: string } | { email: string; code: string }
  'setup_accounts.create': { setup_token: string; email: string; name?: string }
  'passkey_registrations.create': Record<string, never>
  'passkey_registrations.verify': { response: unknown; name?: string }
  'passkey_sign_ins.create': Record<string, never>
  'passkey_sign_ins.verify': { response: unknown }
  'passkeys.list': Record<string, never>
  'passkeys.update': { id: string; name: string }
  'passkeys.delete': { id: string }
  'sessions.get': Record<string, never>
  'sessions.list': Record<string, never>
  'sessions.delete': { id?: string }
  'reauthentications.create': { method: 'email' | 'passkey' }
  'reauthentications.verify': { method: 'email'; code: string } | { method: 'passkey'; response: unknown }
  'users.list': { query?: string; role?: Role; include_deactivated?: boolean; cursor?: string; limit?: number }
  'users.get': { id: string }
  'users.update': { id?: string; name?: string; username?: string; preferences?: Record<string, unknown>; role?: Role; deactivated?: boolean }
  'invites.list': { status?: 'pending' | 'accepted' | 'expired' | 'all'; cursor?: string; limit?: number }
  'invites.create': { email: string; role?: Role }
  'invites.delete': { id: string }
  'invite_acceptances.get': { token: string }
  'invite_acceptances.create': { token: string; name?: string }
  'api_keys.list': Record<string, never>
  'api_keys.create': { name: string; expires_at?: string | null }
  'api_keys.delete': { id: string }
  'settings.list': Record<string, never>
  'settings.update': { key: 'instance.name'; value: string }
  'certificate_authorities.list': { cursor?: string; limit?: number }
  'certificate_authorities.get': { id: string }
  'certificate_authorities.create':
    | (CaCreateCommon & { signing: 'self_signed'; validity_days: number })
    | (CaCreateCommon & { signing: 'internal'; parent_ca_id: string; validity_days: number })
    | (CaCreateCommon & { signing: 'external' })
  'certificate_authorities.import': { id: string; certificate: string; chain?: string }
  'certificate_authorities.renew': { id: string; validity_days?: number }
  'certificate_authorities.archive': { id: string }
  'template_presets.list': Record<string, never>
  'templates.list': { ca_id?: string; status?: TemplateStatus; cursor?: string; limit?: number }
  'templates.get': { id: string }
  'templates.create': Partial<TemplateSettingsInput> & { name: string; slug: string; description?: string; ca_id: string; preset?: TemplatePresetId; tag_ids?: string[] }
  'templates.update': Partial<TemplateSettingsInput> & { id: string; name?: string; description?: string; ca_id?: string; tag_ids?: string[] }
  'templates.archive': { id: string }
  'acme_eab_keys.list': { template_id: string }
  'acme_eab_keys.create': { template_id: string; name: string }
  'acme_eab_keys.revoke': { id: string }
  'est_credentials.list': { template_id: string }
  'est_credentials.create': { template_id: string; name: string }
  'est_credentials.revoke': { id: string }
  'certificates.list': {
    status?: CertificateStatus
    ca_id?: string
    template_id?: string
    source?: CertificateSource
    imported?: boolean
    expiring_before?: string
    query?: string
    tag_ids?: string[]
    untagged?: boolean
    sort?: CertificateSort
    cursor?: string
    limit?: number
  }
  'certificates.get': { id: string }
  'certificates.update': { id: string; tag_ids: string[] }
  'certificate_groups.list': CertificateFilter & { group_by: CertificateGroupBy }
  'tags.list': Record<string, never>
  'tags.create': { name: string; color: string }
  'tags.update': { id: string; name?: string; color?: string }
  'tags.delete': { id: string }
  'certificates.issue': { template_id: string; csr?: string; keygen?: KeygenInput; common_name?: string; sans?: SanInput[]; ttl_seconds?: number; tag_ids?: string[] }
  'certificates.renew': { id: string; csr?: string; keygen?: KeygenInput; ttl_seconds?: number }
  'certificate_stats.get': Record<string, never>
  'dashboard.get': Record<string, never>
  'certificates.revoke': { id: string; reason: LeafRevocationReason }
  'certificates.import': { pem: string; notes?: string; tag_ids?: string[] }
  'certificate_authorities.revoke': { id: string; reason: CaRevocationReason }
  'trust_bundles.list': { cursor?: string; limit?: number }
  'trust_bundles.get': { id: string }
  'trust_bundles.create': { name: string; slug: string; description?: string; ca_ids: string[]; include_chain?: boolean } & TrustBundleTraefikInput
  'trust_bundles.update': { id: string; name?: string; description?: string; ca_ids?: string[]; include_chain?: boolean } & TrustBundleTraefikInput
  'trust_bundles.delete': { id: string }
  'trust_bundles.regenerate_traefik_token': { id: string }
  'alert_channels.list': { cursor?: string; limit?: number }
  'alert_channels.create': { kind: 'email'; name: string; recipients: string[] } | { kind: 'webhook'; name: string; url: string }
  'alert_channels.update': { id: string; name?: string; recipients?: string[]; url?: string; rotate_secret?: boolean }
  'alert_channels.delete': { id: string }
  'alert_channel_tests.create': { channel_id: string }
  'alert_rules.list': { cursor?: string; limit?: number }
  'alert_rules.create': AlertRuleInput
  'alert_rules.update': Partial<AlertRuleInput> & { id: string }
  'alert_rules.delete': { id: string }
  'alert_deliveries.list': { status?: AlertDeliveryStatus; rule_id?: string; channel_id?: string; cursor?: string; limit?: number }
  'events.list': {
    actor_id?: string
    actor_type?: AuditActorType
    name?: string
    subject_type?: string
    subject_id?: string
    from?: string
    to?: string
    cursor?: string
    limit?: number
  }
  'ssh_cas.list': { cursor?: string; limit?: number }
  'ssh_cas.get': { id: string }
  'ssh_cas.create': { name: string; slug: string; description?: string; key_algorithm?: 'ed25519' | 'ecdsa-p256' | 'rsa-4096' }
  'ssh_cas.import': { name: string; slug: string; description?: string; private_key: string }
  'ssh_cas.update': { id: string; name?: string; description?: string }
  'ssh_cas.delete': { id: string }
  'ssh_host_groups.list': { ssh_ca_id?: string; cursor?: string; limit?: number }
  'ssh_host_groups.get': { id: string }
  'ssh_host_groups.create': { name: string; slug: string; ssh_ca_id: string } & SshHostGroupSettings
  'ssh_host_groups.update': { id: string; name?: string } & SshHostGroupSettings
  'ssh_host_groups.delete': { id: string }
  'ssh_access_rules.list': { host_group_id?: string; group_id?: string; cursor?: string; limit?: number }
  'ssh_access_rules.create': { host_group_id: string; group_id: string; logins?: string[]; own_username?: boolean }
  'ssh_access_rules.update': { id: string; logins?: string[]; own_username?: boolean }
  'ssh_access_rules.delete': { id: string }
  'groups.list': { cursor?: string; limit?: number }
  'groups.get': { id: string }
  'groups.create': { name: string; description?: string; provider_groups?: string[] }
  'groups.update': { id: string; name?: string; description?: string; provider_groups?: string[] }
  'groups.delete': { id: string }
  'group_members.list': { group_id: string; cursor?: string; limit?: number }
  'group_members.create': { group_id: string; user_id: string }
  'group_members.delete': { group_id: string; user_id: string }
  'ssh_hosts.list': { host_group_id?: string; query?: string; cursor?: string; limit?: number }
  'ssh_hosts.get': { id: string }
  'ssh_hosts.create': { host_group_id: string; name?: string; hostnames: string[]; public_keys: string[] }
  'ssh_hosts.update': { id: string; name?: string; host_group_id?: string; hostnames?: string[]; public_keys?: string[] }
  'ssh_hosts.delete': { id: string }
  'ssh_join_tokens.list': { host_group_id?: string; status?: 'open' | 'used' | 'expired'; cursor?: string; limit?: number }
  'ssh_join_tokens.create': { host_group_id: string; label?: string; ttl_seconds?: number }
  'ssh_join_tokens.delete': { id: string }
  'ssh_certificates.list': {
    kind?: 'user' | 'host'
    user_id?: string
    host_id?: string
    host_group_id?: string
    ssh_ca_id?: string
    status?: 'active' | 'revoked' | 'expired'
    cursor?: string
    limit?: number
  }
  'ssh_certificates.get': { id: string }
  'ssh_certificates.revoke': { id: string; reason?: string }
  'ssh_user_certificates.sign': { host_group_id: string; public_key: string; ttl_seconds?: number; attestation?: string; attestation_challenge?: string; for_user_id?: string }
  'ssh_access.get': Record<string, never>
  'ssh_hosts.reachable': { cursor?: string; limit?: number }
  'cli_logins.get': { login_id: string }
  'cli_logins.approve': { login_id: string }
  'cli_logins.deny': { login_id: string }
  'cli_sessions.list': Record<string, never>
  'cli_sessions.delete': { id?: string }
}

export type RpcName = keyof RpcInput

export type ApiErrorBody = { error: { code: string; message: string; error_id?: string; details?: Record<string, unknown> } }
/** `users.list` → `users/list`: each endpoint lives at `/api/v2/<resource>/<action>`. */
type DotsToSlashes<S extends string> = S extends `${infer Head}.${infer Tail}` ? `${Head}/${DotsToSlashes<Tail>}` : S
type Endpoint<N extends string> = `/api/v2/${DotsToSlashes<N>}` extends infer K extends keyof InternalApi ? InternalApi[K] : never

/** Successful response body, inferred from the server handler so both sides stay in sync. */
export type RpcOutput<N extends RpcName> = Endpoint<N> extends { post: infer R } ? Exclude<R, ApiErrorBody> : never

/** What the caller may do with an object, e.g. `{ update: true, delete: false }`; every API object carries its own. */
export type Permissions = Record<string, boolean>

export type User = RpcOutput<'sessions.get'>['data']['user']
export type Session = NonNullable<RpcOutput<'sessions.get'>['data']['session']>
/** A person as admins see them. `users.list` also answers operators with the short `Person` card. */
export type Member = RpcOutput<'users.get'>['data']
export type Person = Pick<Member, 'id' | 'name' | 'email' | 'username'>
export type Invite = RpcOutput<'invites.list'>['data'][number]
export type ApiKey = RpcOutput<'api_keys.list'>['data'][number]
export type Passkey = RpcOutput<'passkeys.list'>['data'][number]
export type AuditEvent = RpcOutput<'events.list'>['data'][number]
export type CertificateAuthority = RpcOutput<'certificate_authorities.list'>['data'][number]
export type CertificateAuthorityDetail = RpcOutput<'certificate_authorities.get'>['data']
export type CaStatus = CertificateAuthority['status']
export type CaSigning = CertificateAuthority['signing']
export type Template = RpcOutput<'templates.list'>['data'][number]
export type TemplatePreset = RpcOutput<'template_presets.list'>['data'][number]
export type Certificate = RpcOutput<'certificates.list'>['data'][number]
export type CertificateDetail = RpcOutput<'certificates.get'>['data']
export type IssueResult = RpcOutput<'certificates.issue'>['data']
export type CertificateStats = RpcOutput<'certificate_stats.get'>['data']
export type Dashboard = RpcOutput<'dashboard.get'>['data']
export type ImportResult = RpcOutput<'certificates.import'>['data']
export type TrustBundle = RpcOutput<'trust_bundles.list'>['data'][number]
export type TrustBundleDetail = RpcOutput<'trust_bundles.get'>['data']
export type AlertChannel = RpcOutput<'alert_channels.list'>['data'][number]
export type AlertRule = RpcOutput<'alert_rules.list'>['data'][number]
export type AlertDelivery = RpcOutput<'alert_deliveries.list'>['data'][number]

export type SshCa = RpcOutput<'ssh_cas.list'>['data'][number]
export type SshHostGroup = RpcOutput<'ssh_host_groups.list'>['data'][number]
export type SshAccessRule = RpcOutput<'ssh_access_rules.list'>['data'][number]
export type Group = RpcOutput<'groups.list'>['data'][number]
export type GroupMember = RpcOutput<'group_members.list'>['data'][number]
export type SshHost = RpcOutput<'ssh_hosts.list'>['data'][number]
export type SshJoinToken = RpcOutput<'ssh_join_tokens.list'>['data'][number]
export type SshCertificate = RpcOutput<'ssh_certificates.list'>['data'][number]
export type CliLogin = RpcOutput<'cli_logins.get'>['data']
export type CliSession = RpcOutput<'cli_sessions.list'>['data'][number]

export type CertificateSort = 'newest' | 'expiry' | 'name'
export type CertificateGroupBy = 'tag' | 'template' | 'ca' | 'status'
/** The filters `certificates.list` and `certificate_groups.list` share. */
export type CertificateFilter = Omit<RpcInput['certificates.list'], 'cursor' | 'limit' | 'sort'>
export type Tag = RpcOutput<'tags.list'>['data'][number]
export type CertificateGroup = RpcOutput<'certificate_groups.list'>['data'][number]
