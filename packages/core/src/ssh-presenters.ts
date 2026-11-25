import type { schema } from '@certifly/db'
import type { CliLoginRow, CliSessionRow } from './cli-auth'
import type { GroupRow } from './groups'
import { type Actor, sshAccessPolicy, sshCaPolicy, sshCertificatePolicy, sshHostGroupPolicy, sshHostPolicy, sshJoinTokenPolicy, sshSecurityKeyPolicy } from './policies'
import type { HostGroupAccess, SshAccessRuleListRow } from './ssh-access'
import type { SshCaRow } from './ssh-cas'
import type { SshCertificateListRow, SshCertificateRow } from './ssh-certificates'
import type { SshHostGroupListRow } from './ssh-host-groups'
import { securityKeyModel, type SshSecurityKeyEnrollmentRow, type SshSecurityKeyListRow, type SshSecurityKeyRow } from './ssh-security-keys'
import type { HostSync, SshHostListRow, SshJoinTokenListRow, SshJoinTokenRow } from './ssh-hosts'

type UserRow = typeof schema.users.$inferSelect
const iso = (date: Date | null) => date?.toISOString() ?? null

export function presentSshCa(actor: Actor, ca: SshCaRow & { host_group_count?: number }) {
  return {
    id: ca.id,
    slug: ca.slug,
    name: ca.name,
    description: ca.description,
    key_algorithm: ca.key_algorithm,
    source: ca.source,
    public_key: ca.public_key,
    fingerprint: ca.fingerprint,
    host_group_count: ca.host_group_count ?? 0,
    public_key_url: `/api/pki/ssh/${ca.slug}.pub`,
    krl_url: `/api/pki/ssh/${ca.slug}.krl`,
    created_at: ca.created_at.toISOString(),
    permissions: sshCaPolicy.abilities(actor, undefined),
  }
}

export function presentSshHostGroup(actor: Actor, group: SshHostGroupListRow) {
  return {
    id: group.id,
    slug: group.slug,
    name: group.name,
    description: group.description,
    ca: { id: group.ca.id, slug: group.ca.slug, name: group.ca.name },
    host_patterns: group.host_patterns,
    user_ttl_default_seconds: group.user_ttl_default_seconds,
    user_ttl_max_seconds: group.user_ttl_max_seconds,
    user_extensions: group.user_extensions,
    force_command: group.force_command,
    source_address: group.source_address,
    key_policy: group.key_policy,
    host_ttl_seconds: group.host_ttl_seconds,
    host_count: group.host_count,
    rule_count: group.rule_count,
    created_at: group.created_at.toISOString(),
    permissions: sshHostGroupPolicy.abilities(actor, undefined),
  }
}

export function presentGroup(actor: Actor, group: GroupRow & { member_count: number }) {
  return {
    id: group.id,
    name: group.name,
    description: group.description,
    provider_groups: group.provider_groups,
    member_count: group.member_count,
    created_at: group.created_at.toISOString(),
    permissions: sshAccessPolicy.abilities(actor, undefined),
  }
}

export function presentGroupMember(actor: Actor, row: { user: UserRow; source: 'manual' | 'oidc'; added_at: Date }) {
  return {
    user_id: row.user.id,
    name: row.user.name,
    email: row.user.email,
    source: row.source,
    added_at: row.added_at.toISOString(),
    permissions: { delete: sshAccessPolicy.can(actor, 'manage', undefined) && row.source === 'manual' },
  }
}

export function presentSshAccessRule(actor: Actor, rule: SshAccessRuleListRow) {
  return {
    id: rule.id,
    host_group: rule.host_group,
    group: rule.group,
    logins: rule.logins,
    own_username: rule.own_username,
    created_at: rule.created_at.toISOString(),
    permissions: sshAccessPolicy.abilities(actor, undefined),
  }
}

export function presentSshHost(actor: Actor, host: SshHostListRow) {
  return {
    id: host.id,
    name: host.name,
    host_group: host.host_group,
    hostnames: host.hostnames,
    public_keys: host.public_keys,
    last_seen_at: iso(host.last_seen_at),
    certificate: host.certificate ? { id: host.certificate.id, serial: host.certificate.serial.toString(), valid_before: host.certificate.valid_before.toISOString() } : null,
    created_at: host.created_at.toISOString(),
    permissions: sshHostPolicy.abilities(actor, undefined),
  }
}

export function presentJoinToken(actor: Actor, token: SshJoinTokenListRow | (SshJoinTokenRow & { host_group?: SshJoinTokenListRow['host_group']; host?: SshJoinTokenListRow['host'] }), secret?: string) {
  return {
    id: token.id,
    label: token.label,
    last4: token.last4,
    host_group: token.host_group ?? { id: token.host_group_id },
    host: token.host ?? null,
    created_by: ('created_by' in token ? token.created_by : null) ?? null,
    expires_at: token.expires_at.toISOString(),
    used_at: iso(token.used_at),
    created_at: token.created_at.toISOString(),
    /** Only in the answer that creates the token. */
    ...(secret ? { token: secret } : {}),
    permissions: sshJoinTokenPolicy.abilities(actor, undefined),
  }
}

export function presentSshCertificate(actor: Actor, cert: SshCertificateRow | SshCertificateListRow) {
  const detail = cert as Partial<SshCertificateListRow>
  const now = Date.now()
  return {
    id: cert.id,
    kind: cert.kind,
    serial: cert.serial.toString(),
    key_id: cert.key_id,
    principals: cert.principals,
    fingerprint: cert.fingerprint,
    public_key: cert.public_key,
    certificate: cert.certificate,
    valid_after: cert.valid_after.toISOString(),
    valid_before: cert.valid_before.toISOString(),
    status: (cert.revoked_at ? 'revoked' : cert.valid_before.getTime() <= now ? 'expired' : 'active') as 'revoked' | 'expired' | 'active',
    attested: cert.attested,
    ssh_ca_id: cert.ssh_ca_id,
    host_group: detail.host_group ?? (cert.host_group_id ? { id: cert.host_group_id } : null),
    user: detail.user ?? (cert.user_id ? { id: cert.user_id } : null),
    host: detail.host ?? (cert.host_id ? { id: cert.host_id } : null),
    requested_by_user_id: cert.requested_by_user_id,
    revoked_at: iso(cert.revoked_at),
    revocation_reason: cert.revocation_reason,
    created_at: cert.created_at.toISOString(),
    permissions: {
      read: sshCertificatePolicy.can(actor, 'read', cert),
      revoke: sshCertificatePolicy.can(actor, 'revoke', cert) && !cert.revoked_at && cert.valid_before.getTime() > now,
    },
  }
}

/** What `ssh_user_certificates.sign` returns. */
export function presentSignedUserCertificate(cert: SshCertificateRow) {
  return {
    id: cert.id,
    certificate: cert.certificate,
    serial: cert.serial.toString(),
    key_id: cert.key_id,
    principals: cert.principals,
    valid_after: cert.valid_after.toISOString(),
    valid_before: cert.valid_before.toISOString(),
  }
}

/** What `ssh_access.get` returns. */
export function presentSshAccess(user: { id: string }, username: string, access: HostGroupAccess[]) {
  return {
    user: { id: user.id, username },
    host_groups: access.map((a) => ({
      id: a.host_group.id,
      slug: a.host_group.slug,
      name: a.host_group.name,
      logins: a.logins,
      principals: a.principals,
      key_policy: a.host_group.key_policy,
      default_ttl_seconds: a.host_group.user_ttl_default_seconds,
      max_ttl_seconds: a.host_group.user_ttl_max_seconds,
      extensions: a.host_group.user_extensions,
      host_patterns: a.host_group.host_patterns,
      ca: { id: a.ca.id, slug: a.ca.slug, name: a.ca.name, public_key: a.ca.public_key },
    })),
  }
}

export function presentReachableHost(row: { host: typeof schema.sshHosts.$inferSelect; host_group: typeof schema.sshHostGroups.$inferSelect; logins: string[] }) {
  return {
    id: row.host.id,
    name: row.host.name,
    hostnames: row.host.hostnames,
    host_group: { id: row.host_group.id, slug: row.host_group.slug, name: row.host_group.name },
    logins: row.logins,
    last_seen_at: iso(row.host.last_seen_at),
  }
}

export function presentHostSync(sync: HostSync) {
  return sync
}

export function presentCliLogin(login: CliLoginRow) {
  return {
    id: login.id,
    user_code: login.user_code,
    machine: { hostname: login.machine_hostname, os: login.machine_os },
    status: login.status,
    expires_at: login.expires_at.toISOString(),
  }
}

export function presentCliSession(session: CliSessionRow, current: boolean) {
  return {
    id: session.id,
    machine: { hostname: session.machine_hostname, os: session.machine_os },
    created_at: session.created_at.toISOString(),
    expires_at: session.expires_at.toISOString(),
    last_used_at: iso(session.last_used_at),
    current,
    permissions: { delete: true },
  }
}

export function presentSshSecurityKey(actor: Actor, key: SshSecurityKeyListRow) {
  const active = !key.revoked_at
  return {
    id: key.id,
    user_id: key.user_id,
    name: key.name,
    public_key: key.public_key,
    fingerprint: key.fingerprint,
    application: key.application,
    model: securityKeyModel(key.aaguid, key.attested),
    attested: key.attested,
    machine: key.machine,
    created_at: key.created_at.toISOString(),
    last_used_at: iso(key.last_used_at),
    revoked_at: iso(key.revoked_at),
    revoked_by: key.revoked_by,
    active_certificates: key.active_certificates,
    permissions: {
      update: active && sshSecurityKeyPolicy.can(actor, 'update', key),
      revoke: active && sshSecurityKeyPolicy.can(actor, 'revoke', key),
    },
  }
}

/** What the CLI learns about its newly registered key. */
export function presentRegisteredSecurityKey(key: SshSecurityKeyRow) {
  return { id: key.id, name: key.name, public_key: key.public_key, fingerprint: key.fingerprint, model: securityKeyModel(key.aaguid, key.attested), attested: key.attested }
}

export function presentSshSecurityKeyEnrollment(enrollment: SshSecurityKeyEnrollmentRow) {
  return {
    id: enrollment.id,
    status: enrollment.status,
    user_code: enrollment.user_code,
    machine: { hostname: enrollment.machine_hostname, os: enrollment.machine_os },
    name: enrollment.name,
    public_key: enrollment.public_key,
    fingerprint: enrollment.fingerprint,
    model: securityKeyModel(enrollment.aaguid, enrollment.attested),
    attested: enrollment.attested,
    expires_at: enrollment.expires_at.toISOString(),
  }
}
