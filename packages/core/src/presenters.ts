import { type CertificateInfo, revocationReasonName } from '@certifly/pki'
import type { EventRow } from './audit'
import type { ApiKeyRow } from './api-keys'
import type { CaCertificateRow, CaDetail, CaListRow, CaRow } from './cas'
import { inviteStatus, type InviteRow } from './invites'
import { isRecentlyReauthenticated, type SessionRow, STEP_UP_MAX_AGE_MS } from './auth/sessions'
import { type Actor, apiKeyPolicy, auditPolicy, caPolicy, invitePolicy, peoplePolicy, settingsPolicy, userPolicy } from './policies'
import type { UserRow } from './users'
import type { schema } from '@certifly/db'
import { type CertificateDetail, type CertificateGroup, type CertificateListRow, effectiveStatus, type IssueResult } from './certificates'
import { alertPolicy, certificatePolicy, sshAccessPolicy, sshCaPolicy, sshCertificatePolicy, sshHostGroupPolicy, sshHostPolicy, sshJoinTokenPolicy, tagPolicy, templatePolicy, trustBundlePolicy } from './policies'
import type { AcmeEabKeyRow } from './acme'
import type { EstCredentialRow } from './est'
import type { TagListRow, TagSummary } from './tags'
import type { TemplateWithCa } from './templates'
import type { AlertChannelResult, AlertChannelRow, AlertDeliveryListRow, AlertRuleRow, CaFacts, CertificateFacts } from './alerts'
import type { ImportCertificatesResult } from './inventory'
import { traefikRefs } from './traefik'
import type { BundleCa, TrustBundleDetail, TrustBundleRow } from './trust-bundles'

const iso = (date: Date | null) => date?.toISOString() ?? null

/** Presenters decide which fields leave the server and add what the viewer may do (`permissions`). */

export function presentUser(actor: Actor, user: UserRow) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    /** The SSH username; null until it is first needed, then the email's local part unless an admin set another. */
    username: user.username,
    role: user.role,
    preferences: user.preferences,
    last_active_at: iso(user.last_active_at),
    last_signed_in_at: iso(user.last_signed_in_at),
    created_at: user.created_at.toISOString(),
    deleted_at: iso(user.deleted_at),
    permissions: userPolicy.abilities(actor, user),
  }
}

/**
 * A person as an operator sees someone else: enough to pick them, nothing about their role,
 * sign-ins or sessions.
 */
function presentPerson(user: UserRow) {
  return { id: user.id, name: user.name, email: user.email, username: user.username }
}

/** A row of `users.list`: complete for admins and for the person themselves, a short card for anyone else. */
export function presentListedUser(actor: Actor, user: UserRow) {
  return peoplePolicy.can(actor, 'list', undefined) || user.id === actor.id ? presentUser(actor, user) : presentPerson(user)
}

export function presentApiKey(actor: Actor, key: ApiKeyRow) {
  return {
    id: key.id,
    name: key.name,
    last4: key.last4,
    expires_at: iso(key.expires_at),
    last_used_at: iso(key.last_used_at),
    created_at: key.created_at.toISOString(),
    permissions: apiKeyPolicy.abilities(actor, key),
  }
}

export function presentInvite(actor: Actor, invite: InviteRow) {
  return {
    id: invite.id,
    email: invite.email,
    role: invite.role,
    status: inviteStatus(invite),
    invited_by_id: invite.invited_by_id,
    expires_at: invite.expires_at.toISOString(),
    accepted_at: iso(invite.accepted_at),
    created_at: invite.created_at.toISOString(),
    permissions: invitePolicy.abilities(actor, undefined),
  }
}

/** An audit entry as `listEvents` returns it: the row plus the acting user's name, if any. */
export function presentEvent(actor: Actor, row: { event: EventRow; actor_name: string | null }) {
  const { event } = row
  return {
    id: event.id,
    actor_type: event.actor_type,
    actor_id: event.actor_id,
    actor_name: row.actor_name,
    name: event.name,
    subject_type: event.subject_type,
    subject_id: event.subject_id,
    data: event.data,
    ip: event.ip,
    created_at: event.created_at.toISOString(),
    permissions: auditPolicy.abilities(actor, undefined),
  }
}

/** A passkey belongs to the person using it, so it has no permissions of its own. */
export function presentPasskey(passkey: typeof schema.passkeys.$inferSelect) {
  return {
    id: passkey.id,
    name: passkey.name,
    created_at: passkey.created_at.toISOString(),
    last_used_at: iso(passkey.last_used_at),
  }
}

/**
 * A session as its owner sees it. `reauth_fresh` says whether sensitive actions are open
 * right now; it turns false once the last re-authentication is older than `reauth_max_age_seconds`.
 */
export function presentSession(session: SessionRow, currentId: string | null) {
  return {
    id: session.id,
    current: session.id === currentId,
    user_agent: session.user_agent,
    ip_address: session.ip_address,
    reauth_at: iso(session.reauth_at),
    reauth_fresh: isRecentlyReauthenticated(session),
    reauth_max_age_seconds: STEP_UP_MAX_AGE_MS / 1000,
    last_active_at: session.last_active_at.toISOString(),
    created_at: session.created_at.toISOString(),
    expires_at: session.expires_at.toISOString(),
  }
}

/**
 * What the actor may do that belongs to no single object, such as listing the audit log or
 * managing people. The client reads these with `auth.can('instance', …)` instead of looking at roles.
 */
export function presentInstance(actor: Actor) {
  return {
    id: 'instance',
    permissions: {
      read_events: auditPolicy.can(actor, 'read', undefined),
      read_settings: settingsPolicy.can(actor, 'read', undefined),
      update_settings: settingsPolicy.can(actor, 'update', undefined),
      manage_users: invitePolicy.can(actor, 'read', undefined),
      read_certificate_authorities: caPolicy.can(actor, 'read', undefined),
      create_certificate_authority: caPolicy.can(actor, 'create', undefined),
      read_templates: templatePolicy.can(actor, 'read', undefined),
      create_template: templatePolicy.can(actor, 'create', undefined),
      read_certificates: certificatePolicy.can(actor, 'read', undefined),
      issue_certificate: certificatePolicy.can(actor, 'issue', undefined),
      import_certificates: certificatePolicy.can(actor, 'import', undefined),
      update_certificate_tags: certificatePolicy.can(actor, 'update', undefined),
      read_tags: tagPolicy.can(actor, 'read', undefined),
      manage_tags: tagPolicy.can(actor, 'create', undefined),
      read_trust_bundles: trustBundlePolicy.can(actor, 'read', undefined),
      create_trust_bundle: trustBundlePolicy.can(actor, 'create', undefined),
      read_alerts: alertPolicy.can(actor, 'read', undefined),
      manage_alerts: alertPolicy.can(actor, 'manage', undefined),
      read_alert_deliveries: alertPolicy.can(actor, 'read_deliveries', undefined),
      read_ssh_cas: sshCaPolicy.can(actor, 'read', undefined),
      create_ssh_ca: sshCaPolicy.can(actor, 'create', undefined),
      read_ssh_host_groups: sshHostGroupPolicy.can(actor, 'read', undefined),
      manage_ssh_host_groups: sshHostGroupPolicy.can(actor, 'manage', undefined),
      read_groups: sshAccessPolicy.can(actor, 'read', undefined),
      manage_groups: sshAccessPolicy.can(actor, 'manage', undefined),
      read_ssh_hosts: sshHostPolicy.can(actor, 'read', undefined),
      manage_ssh_hosts: sshHostPolicy.can(actor, 'manage', undefined),
      read_ssh_join_tokens: sshJoinTokenPolicy.can(actor, 'read', undefined),
      create_ssh_join_token: sshJoinTokenPolicy.can(actor, 'create', undefined),
      read_ssh_certificates: sshCertificatePolicy.can(actor, 'read', undefined),
      sign_ssh_for_others: sshCertificatePolicy.can(actor, 'sign_for_others', undefined),
    },
  }
}

/**
 * What the actor may do with a CA right now: the role rules of `caPolicy`, narrowed to the
 * actions that fit the CA's state (only externally signed CAs take an import; nothing changes
 * a disabled CA).
 */
function caPermissions(actor: Actor, ca: CaRow) {
  const role = caPolicy.abilities(actor, undefined)
  const live = ca.status !== 'disabled'
  return {
    read: role.read,
    import: role.import && live && ca.signing === 'external',
    renew: role.renew && live && (ca.signing === 'external' || ca.status !== 'pending_certificate'),
    disable: role.disable && live,
    // Internal CAs are revoked on the parent's CRL, externally signed ones marked compromised; a root has neither.
    revoke: role.revoke && !ca.revoked_at && ca.signing !== 'self_signed',
  }
}

/** A CA as lists show it. `chain_subjects` names the outside chain of an externally signed CA, issuer first. */
export function presentCertificateAuthority(actor: Actor, row: CaListRow) {
  const { ca } = row
  return {
    id: ca.id,
    slug: ca.slug,
    name: ca.name,
    description: ca.description,
    signing: ca.signing,
    parent_ca_id: ca.parent_ca_id,
    status: ca.status,
    subject_dn: ca.subject_dn,
    issuer_dn: row.issuer_dn,
    chain_subjects: row.chain_subjects,
    key_algorithm: ca.key_algorithm,
    max_path_length: ca.max_path_length,
    name_constraints: ca.name_constraints,
    crl_validity_hours: ca.crl_validity_hours,
    crl_overlap_hours: ca.crl_overlap_hours,
    not_before: iso(ca.not_before),
    not_after: iso(ca.not_after),
    disabled_at: iso(ca.disabled_at),
    /** For an externally signed CA, when it was marked compromised; it still has to be revoked at its issuer. */
    revoked_at: iso(ca.revoked_at),
    revocation_reason: ca.revocation_reason === null ? null : revocationReasonName(ca.revocation_reason),
    created_at: ca.created_at.toISOString(),
    updated_at: ca.updated_at.toISOString(),
    permissions: caPermissions(actor, ca),
  }
}

/** Decoded certificate fields for display; no raw key bytes. */
function presentCertificateInfo(info: CertificateInfo) {
  return {
    serial: info.serial,
    subject: info.subject,
    issuer: info.issuer,
    not_before: info.not_before.toISOString(),
    not_after: info.not_after.toISOString(),
    fingerprint_sha256: info.fingerprint_sha256,
    fingerprint_sha1: info.fingerprint_sha1,
    self_issued: info.self_issued,
    is_ca: info.is_ca,
    path_length: info.path_length,
    key_usages: info.key_usages,
    extended_key_usages: info.extended_key_usages,
    extended_key_usage_names: info.extended_key_usage_names,
    subject_key_identifier: info.subject_key_identifier,
    authority_key_identifier: info.authority_key_identifier,
    crl_urls: info.crl_urls,
    ca_issuer_urls: info.ca_issuer_urls,
    name_constraints: info.name_constraints,
    public_key: info.public_key ? { type: info.public_key.type, key_algorithm: info.public_key.key_algorithm, bits: info.public_key.bits } : null,
    pem: info.pem,
  }
}

function presentCaVersion(version: CaCertificateRow, activeId: string | null) {
  return {
    id: version.id,
    version: version.version,
    key_id: version.key_id,
    serial: version.serial,
    issuer_dn: version.issuer_dn,
    not_before: version.not_before.toISOString(),
    not_after: version.not_after.toISOString(),
    fingerprint_sha256: version.fingerprint_sha256,
    active: version.id === activeId,
    revoked_at: iso(version.revoked_at),
    created_at: version.created_at.toISOString(),
  }
}

/**
 * A CA with everything its page shows. The CSR, certificate and chain come as PEM text so the
 * page can offer them as downloads; the DER forms are at the public URLs.
 */
export function presentCertificateAuthorityDetail(actor: Actor, detail: CaDetail) {
  const { ca } = detail
  return {
    ...presentCertificateAuthority(actor, {
      ca,
      issuer_dn: detail.active_certificate?.issuer ?? null,
      chain_subjects: ca.signing === 'external' ? detail.chain.map((c) => c.subject) : [],
    }),
    active_certificate: detail.active_certificate ? presentCertificateInfo(detail.active_certificate) : null,
    chain: detail.chain.map(presentCertificateInfo),
    chain_pem: detail.chain_pem,
    versions: detail.versions.map((v) => presentCaVersion(v, ca.active_cert_id)),
    pending_csr: detail.pending_csr
      ? { id: detail.pending_csr.id, key_id: detail.pending_csr.key_id, pem: detail.pending_csr.csr_pem, requested_path_length: detail.pending_csr.requested_path_length, created_at: detail.pending_csr.created_at.toISOString() }
      : null,
    crl: detail.crl
      ? { crl_number: detail.crl.crl_number.toString(), this_update: detail.crl.this_update.toISOString(), next_update: detail.crl.next_update.toISOString() }
      : null,
    crls: detail.crls.map((crl) => ({
      key_id: crl.key_id,
      active: crl.active,
      url: crl.url,
      crl_number: crl.crl_number.toString(),
      this_update: crl.this_update.toISOString(),
      next_update: crl.next_update.toISOString(),
    })),
    parent: detail.parent && { ...detail.parent, not_after: iso(detail.parent.not_after) },
    ancestors: detail.ancestors.map((entry) => ({ ...entry, not_after: iso(entry.not_after), revoked_at: iso(entry.revoked_at) })),
    children: detail.children.map((child) => ({ ...child, not_after: iso(child.not_after), revoked_at: iso(child.revoked_at) })),
    urls: detail.urls,
  }
}

// ---------------------------------------------------------------------------------------------
// Templates and leaf certificates

/**
 * A short reading of a template's extended key usages for badges: `server` or `client` for
 * serverAuth or clientAuth alone, `server_client` for exactly both, `other` for anything else.
 */
export function usageHint(ekus: readonly string[]): 'server' | 'client' | 'server_client' | 'other' {
  const set = new Set(ekus)
  if (set.size === 1 && set.has('server_auth')) return 'server'
  if (set.size === 1 && set.has('client_auth')) return 'client'
  if (set.size === 2 && set.has('server_auth') && set.has('client_auth')) return 'server_client'
  return 'other'
}

/** A tag as certificates and templates carry it. */
function presentTagSummary(tag: TagSummary) {
  return { id: tag.id, name: tag.name, color: tag.color }
}

/** A tag in the managed list, with how many certificates and templates carry it. */
export function presentTag(actor: Actor, row: TagListRow) {
  const role = tagPolicy.abilities(actor, undefined)
  return {
    id: row.tag.id,
    name: row.tag.name,
    color: row.tag.color,
    certificate_count: row.certificate_count,
    template_count: row.template_count,
    created_at: row.tag.created_at.toISOString(),
    updated_at: row.tag.updated_at.toISOString(),
    permissions: { read: role.read, update: role.update, delete: role.delete },
  }
}

/** One group of the certificate list's group-by view. */
export function presentCertificateGroup(group: CertificateGroup) {
  return { key: group.key, label: group.label, color: group.color, count: group.count, expiring_within_30_days: group.expiring_within_30_days, filter: group.filter }
}

/**
 * A template with its CA. `bound_to_root` lets the UI warn: certificates straight from a root
 * mean the root key signs every day. `max_ttl_exceeds_ca` says the CA runs out sooner than the
 * template's maximum lifetime, so certificates will be cut back to the CA's end.
 */
export function presentTemplate(actor: Actor, row: TemplateWithCa, now = new Date()) {
  const { template, ca } = row
  const live = template.status === 'active'
  const role = templatePolicy.abilities(actor, undefined)
  const ca_remaining_seconds = ca.not_after ? Math.max(0, Math.floor((ca.not_after.getTime() - now.getTime()) / 1000)) : null
  return {
    id: template.id,
    slug: template.slug,
    name: template.name,
    description: template.description,
    ca_id: template.ca_id,
    usage_hint: usageHint(template.extended_key_usages),
    status: template.status,
    allowed_san_types: template.allowed_san_types,
    allowed_dns: template.allowed_dns,
    allowed_ips: template.allowed_ips,
    allow_wildcards: template.allow_wildcards,
    require_san: template.require_san,
    require_common_name: template.require_common_name,
    subject_defaults: template.subject_defaults,
    allowed_subject_fields: template.allowed_subject_fields,
    key_algorithms: template.key_algorithms,
    max_ttl_seconds: template.max_ttl_seconds,
    default_ttl_seconds: template.default_ttl_seconds,
    key_usages: template.key_usages,
    extended_key_usages: template.extended_key_usages,
    allow_server_keygen: template.allow_server_keygen,
    allow_acme: template.allow_acme,
    allow_est: template.allow_est,
    est_base_url: row.est_base_url,
    acme_directory_url: row.acme_directory_url,
    acme_account_count: row.acme_account_count,
    renew_before_days: template.renew_before_days,
    tags: row.tags.map(presentTagSummary),
    archived_at: iso(template.archived_at),
    created_at: template.created_at.toISOString(),
    updated_at: template.updated_at.toISOString(),
    ca: { id: ca.id, name: ca.name, slug: ca.slug, status: ca.status, signing: ca.signing, not_after: iso(ca.not_after), name_constraints: ca.name_constraints },
    bound_to_root: ca.signing === 'self_signed',
    ca_remaining_seconds,
    max_ttl_exceeds_ca: ca_remaining_seconds !== null && template.max_ttl_seconds > ca_remaining_seconds,
    permissions: {
      read: role.read,
      update: role.update && live,
      archive: role.archive && live,
      issue: certificatePolicy.can(actor, 'issue', undefined) && live && ca.status === 'active',
    },
  }
}

/** An EST credential. The password is never part of it; `est_credentials.create` adds it once. */
export function presentEstCredential(actor: Actor, credential: EstCredentialRow) {
  return {
    id: credential.id,
    template_id: credential.template_id,
    name: credential.name,
    username: credential.username,
    created_at: credential.created_at.toISOString(),
    last_used_at: iso(credential.last_used_at),
    revoked_at: iso(credential.revoked_at),
    permissions: { revoke: templatePolicy.can(actor, 'update', undefined) && !credential.revoked_at },
  }
}

/** An ACME binding key. The HMAC key is never part of it; `acme_eab_keys.create` adds it once. */
export function presentAcmeEabKey(actor: Actor, key: AcmeEabKeyRow) {
  return {
    id: key.id,
    template_id: key.template_id,
    name: key.name,
    kid: key.kid,
    created_at: key.created_at.toISOString(),
    last_used_at: iso(key.last_used_at),
    revoked_at: iso(key.revoked_at),
    permissions: { revoke: templatePolicy.can(actor, 'update', undefined) && !key.revoked_at },
  }
}

const DAY_MS = 24 * 60 * 60 * 1000

/** A leaf certificate as lists show it. `status` reads `expired` once notAfter has passed. */
export function presentCertificate(actor: Actor, row: CertificateListRow, now = new Date()) {
  const { certificate: cert, template } = row
  const status = effectiveStatus(cert, now)
  const renewable = (status === 'active' || status === 'expired') && template?.status === 'active'
  return {
    id: cert.id,
    ca_id: cert.ca_id,
    ca_cert_id: cert.ca_cert_id,
    template_id: cert.template_id,
    source: cert.source,
    status,
    serial: cert.serial,
    subject_dn: cert.subject_dn,
    issuer_dn: cert.issuer_dn,
    common_name: cert.common_name,
    sans: cert.sans,
    key_algorithm: cert.key_algorithm,
    key_usages: cert.key_usages,
    extended_key_usages: cert.extended_key_usages,
    not_before: cert.not_before.toISOString(),
    not_after: cert.not_after.toISOString(),
    fingerprint_sha256: cert.fingerprint_sha256,
    key_generated: cert.key_generated,
    superseded_by_id: cert.superseded_by_id,
    revoked_at: iso(cert.revoked_at),
    revocation_reason: cert.revocation_reason === null ? null : revocationReasonName(cert.revocation_reason),
    requested_by_user_id: cert.requested_by_user_id,
    requested_by_api_key_id: cert.requested_by_api_key_id,
    created_at: cert.created_at.toISOString(),
    ca: row.ca,
    template: template ? { id: template.id, name: template.name, slug: template.slug, status: template.status } : null,
    tags: row.tags.map(presentTagSummary),
    /** Inside the template's renewal window (or already expired) and not replaced yet. */
    renew_due: status === 'expired' || (status === 'active' && !!template && cert.not_after.getTime() - template.renew_before_days * DAY_MS <= now.getTime()),
    permissions: {
      read: certificatePolicy.can(actor, 'read', undefined),
      update_tags: certificatePolicy.can(actor, 'update', undefined),
      renew: certificatePolicy.can(actor, 'renew', undefined) && renewable,
      // Imported certificates are revoked by their own issuer; expired ones need no revocation.
      revoke: certificatePolicy.can(actor, 'revoke', undefined) && cert.source !== 'import' && (status === 'active' || status === 'superseded'),
    },
  }
}

/**
 * A certificate with everything its page shows and offers for download: the certificate, the
 * chain (issuing CA up to the root) and the full bundle as PEM. DER is the base64 body of the
 * PEM, so the browser builds that download itself. There is never a private key here.
 */
export function presentCertificateDetail(actor: Actor, detail: CertificateDetail, now = new Date()) {
  return {
    ...presentCertificate(actor, detail, now),
    details: presentCertificateInfo(detail.info),
    pem: detail.info.pem,
    chain_pem: detail.chain_pem,
    bundle_pem: detail.info.pem + detail.chain_pem,
    has_csr: !!detail.certificate.csr_pem,
    supersedes_id: detail.supersedes_id,
  }
}

/** The answer to an issue or renew request. `private_key` is there once, for keygen requests only. */
export function presentIssueResult(actor: Actor, result: IssueResult, detail: CertificateDetail) {
  return {
    certificate: presentCertificateDetail(actor, detail),
    not_after_clamped: result.not_after_clamped,
    ignored_subject_fields: result.ignored_subject_fields,
    private_key: result.private_key ?? null,
  }
}

// ---------------------------------------------------------------------------------------------
// Inventory, trust bundles and alerts

/** The answer to an inventory import: what was stored, and what was skipped and why. */
export function presentImportResult(actor: Actor, result: ImportCertificatesResult) {
  return {
    imported: result.imported.map((cert) => ({
      id: cert.id,
      common_name: cert.common_name,
      subject_dn: cert.subject_dn,
      issuer_dn: cert.issuer_dn,
      serial: cert.serial,
      not_after: cert.not_after.toISOString(),
      fingerprint_sha256: cert.fingerprint_sha256,
    })),
    skipped: result.skipped,
    permissions: { import: certificatePolicy.can(actor, 'import', undefined) },
  }
}

function presentBundleCa(ca: BundleCa) {
  return { id: ca.id, name: ca.name, slug: ca.slug, status: ca.status, signing: ca.signing, revoked: !!ca.revoked_at }
}

/** A trust bundle as lists show it. `path` is the public PEM on this origin, for downloads. */
export function presentTrustBundle(actor: Actor, row: { bundle: TrustBundleRow; cas: BundleCa[]; url: string; traefik_url: string; traefik_token?: string }) {
  const { bundle } = row
  const role = trustBundlePolicy.abilities(actor, undefined)
  return {
    id: bundle.id,
    slug: bundle.slug,
    name: bundle.name,
    description: bundle.description,
    include_chain: bundle.include_chain,
    cas: row.cas.map(presentBundleCa),
    url: row.url,
    path: `/api/pki/bundle/${bundle.slug}.pem`,
    traefik_enabled: bundle.traefik_enabled,
    traefik_client_auth: bundle.traefik_client_auth,
    traefik_client_auth_type: bundle.traefik_client_auth_type,
    traefik_tls_option_name: bundle.traefik_tls_option_name,
    traefik_servers_transport: bundle.traefik_servers_transport,
    traefik_servers_transport_name: bundle.traefik_servers_transport_name,
    traefik_require_token: bundle.traefik_require_token,
    traefik_url: row.traefik_url,
    /** What Traefik routers and services name, e.g. `internal-mtls@http`; null for a part that is off. */
    traefik_refs: traefikRefs(bundle),
    /** The Traefik token in plain text: only in the answer to the call that made it, otherwise null. */
    traefik_token: row.traefik_token ?? null,
    created_at: bundle.created_at.toISOString(),
    updated_at: bundle.updated_at.toISOString(),
    permissions: { read: role.read, update: role.update, delete: role.delete },
  }
}

/** A trust bundle with the certificates its PEM holds right now. */
export function presentTrustBundleDetail(actor: Actor, detail: TrustBundleDetail) {
  return {
    ...presentTrustBundle(actor, detail),
    certificates: detail.certificates.map((cert) => ({
      subject: cert.subject,
      not_after: cert.not_after.toISOString(),
      fingerprint_sha256: cert.fingerprint_sha256,
      ca_id: cert.ca_id,
      from_chain: cert.from_chain,
    })),
  }
}

/**
 * An alert channel. The webhook secret never leaves the server after it was shown once:
 * only `has_secret` says there is one.
 */
export function presentAlertChannel(actor: Actor, channel: AlertChannelRow) {
  const manage = alertPolicy.can(actor, 'manage', undefined)
  const config = channel.config
  return {
    id: channel.id,
    name: channel.name,
    kind: channel.kind,
    recipients: 'recipients' in config ? config.recipients : [],
    url: 'url' in config ? config.url : null,
    has_secret: 'secret_enc' in config,
    created_at: channel.created_at.toISOString(),
    updated_at: channel.updated_at.toISOString(),
    permissions: { read: alertPolicy.can(actor, 'read', undefined), update: manage, delete: manage, test: manage },
  }
}

/** A channel right after it was created or its secret rotated: the secret is here once. */
export function presentAlertChannelResult(actor: Actor, result: AlertChannelResult) {
  return { channel: presentAlertChannel(actor, result.channel), secret: result.secret ?? null }
}

export function presentAlertRule(actor: Actor, rule: AlertRuleRow) {
  const manage = alertPolicy.can(actor, 'manage', undefined)
  return {
    id: rule.id,
    name: rule.name,
    event: rule.event,
    ca_ids: rule.filter.ca_ids,
    template_ids: rule.filter.template_ids,
    include_imported: rule.filter.include_imported,
    days_before: rule.days_before,
    channel_ids: rule.channel_ids,
    enabled: rule.enabled,
    created_at: rule.created_at.toISOString(),
    updated_at: rule.updated_at.toISOString(),
    permissions: { read: alertPolicy.can(actor, 'read', undefined), update: manage, delete: manage },
  }
}

/**
 * One alert delivery for the history. `subject_label` names the certificate or CA it was about;
 * the payload itself stays on the server.
 */
export function presentAlertDelivery(actor: Actor, row: AlertDeliveryListRow) {
  const { delivery } = row
  const payload = delivery.payload as { certificate?: CertificateFacts; certificate_authority?: CaFacts; threshold_days?: number }
  const cert = payload.certificate
  return {
    id: delivery.id,
    event: delivery.event,
    test: delivery.test,
    status: delivery.status,
    attempts: delivery.attempts,
    last_error: delivery.last_error,
    subject_type: delivery.subject_type,
    subject_id: delivery.subject_id,
    subject_label: cert ? (cert.common_name ?? cert.sans[0]?.value ?? cert.serial) : (payload.certificate_authority?.name ?? null),
    threshold_days: payload.threshold_days ?? null,
    rule: row.rule,
    channel: row.channel,
    last_attempt_at: iso(delivery.last_attempt_at),
    sent_at: iso(delivery.sent_at),
    created_at: delivery.created_at.toISOString(),
    permissions: { read: alertPolicy.can(actor, 'read_deliveries', undefined) },
  }
}
