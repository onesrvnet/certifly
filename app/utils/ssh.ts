import type { SshHostGroup, SshHostGroupSettings } from '~/types/api'

export type SshKeyPolicy = NonNullable<SshHostGroupSettings['key_policy']>
export const SSH_KEY_POLICIES: SshKeyPolicy[] = ['any', 'sk', 'sk_attested']

/** The extensions the host group form has a switch for, as OpenSSH names them. */
export const SSH_FORM_EXTENSIONS = ['permit-pty', 'permit-port-forwarding', 'permit-X11-forwarding', 'permit-agent-forwarding'] as const

/** Longest user lifetime a host group may set: 7 days. */
export const SSH_USER_TTL_MAX_HOURS = 168

type Translate = (key: string, params?: Record<string, unknown>) => string

/** "90 d", "8 h", "3 h 12 min", "30 min": a length of time in whole units. */
export function durationLabel(seconds: number, t: Translate): string {
  const total = Math.max(0, Math.round(seconds))
  const days = Math.floor(total / DAY_SECONDS)
  if (days >= 1 && total % DAY_SECONDS === 0) return t('ssh.duration.days', { count: days })
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (hours >= 1 && minutes === 0) return t('ssh.duration.hours', { count: hours })
  if (hours >= 1) return `${t('ssh.duration.hours', { count: hours })} ${t('ssh.duration.minutes', { count: minutes })}`
  return t('ssh.duration.minutes', { count: Math.max(1, minutes) })
}

/** The label of a host's last check-in or a certificate's remaining time. */
export const secondsUntil = (iso: string, now = Date.now()) => Math.round((new Date(iso).getTime() - now) / 1000)

/** A host that has not checked in for this long is likely to have lost contact (sync runs every 15 minutes). */
export const HOST_STALE_SECONDS = 60 * 60
/** A host certificate this close to its end should have been renewed already. */
export const HOST_CERT_WARN_SECONDS = 14 * DAY_SECONDS

export const hostSeenStale = (lastSeen: string | null, now = Date.now()) => !!lastSeen && (now - new Date(lastSeen).getTime()) / 1000 > HOST_STALE_SECONDS
export const hostCertWarn = (validBefore: string | null, now = Date.now()) => !!validBefore && secondsUntil(validBefore, now) < HOST_CERT_WARN_SECONDS

/** What the host group form edits: lifetimes in hours (users) and days (hosts). */
export interface HostGroupFormState {
  name: string
  slug: string
  ssh_ca_id: string
  host_patterns: string[]
  user_ttl_default_hours: number
  user_ttl_max_hours: number
  key_policy: SshKeyPolicy
  /** Every extension, also ones the form has no switch for, so saving keeps them. */
  user_extensions: string[]
  force_command: string
  source_address: string[]
  host_ttl_days: number
}

export function emptyHostGroupForm(caId = ''): HostGroupFormState {
  return {
    name: '',
    slug: '',
    ssh_ca_id: caId,
    host_patterns: [],
    user_ttl_default_hours: 8,
    user_ttl_max_hours: 24,
    key_policy: 'any',
    user_extensions: ['permit-pty'],
    force_command: '',
    source_address: [],
    host_ttl_days: 90,
  }
}

export function hostGroupFormFrom(group: SshHostGroup): HostGroupFormState {
  return {
    name: group.name,
    slug: group.slug,
    ssh_ca_id: group.ca.id,
    host_patterns: [...group.host_patterns],
    user_ttl_default_hours: group.user_ttl_default_seconds / 3600,
    user_ttl_max_hours: group.user_ttl_max_seconds / 3600,
    key_policy: group.key_policy,
    user_extensions: [...group.user_extensions],
    force_command: group.force_command ?? '',
    source_address: [...group.source_address],
    host_ttl_days: group.host_ttl_seconds / DAY_SECONDS,
  }
}

/** The settings part of the request body, shared by create and update. */
export function hostGroupSettings(form: HostGroupFormState): SshHostGroupSettings {
  return {
    host_patterns: form.host_patterns,
    user_ttl_default_seconds: Math.round(form.user_ttl_default_hours * 3600),
    user_ttl_max_seconds: Math.round(form.user_ttl_max_hours * 3600),
    user_extensions: form.user_extensions,
    force_command: form.force_command.trim() || null,
    source_address: form.source_address,
    key_policy: form.key_policy,
    host_ttl_seconds: Math.round(form.host_ttl_days * DAY_SECONDS),
  }
}

export type HostGroupField = 'name' | 'slug' | 'ssh_ca_id' | 'host_patterns' | 'ttl' | 'force_command' | 'source_address' | 'host_ttl'

/** Which field of the host group form a server error code belongs to; other errors go to the top of the form. */
export function hostGroupErrorField(error: unknown): HostGroupField | null {
  if (!(error instanceof RpcError)) return null
  switch (error.code) {
    case 'slug_taken':
    case 'invalid_slug':
      return 'slug'
    case 'invalid_host_pattern':
      return 'host_patterns'
    case 'invalid_ttl':
      return 'ttl'
    case 'invalid_force_command':
      return 'force_command'
    case 'invalid_source_address':
      return 'source_address'
    default:
      return null
  }
}

/** A CA key algorithm as people name it: Ed25519, ECDSA P-256, RSA 4096. */
export function sshKeyLabel(algorithm: string): string {
  if (algorithm === 'ed25519') return 'Ed25519'
  const ecdsa = /^ecdsa-p(\d+)$/.exec(algorithm)
  if (ecdsa) return `ECDSA P-${ecdsa[1]}`
  const rsa = /^rsa-(\d+)$/.exec(algorithm)
  return rsa ? `RSA ${rsa[1]}` : algorithm
}

/** The principals a rule gives: `<slug>:<login>` for each login. */
export const rulePrincipals = (slug: string, logins: string[]) => logins.map((login) => `${slug}:${login}`)

/** The download name of a signed certificate: `<key name>-cert.pub`. */
export const certFileName = (publicKey: string) => `${keyBaseName(publicKey)}-cert.pub`

/** The file name OpenSSH looks for next to a key: `id_ed25519` for an Ed25519 key, so `id_ed25519-cert.pub` is picked up by `ssh`. */
export function keyBaseName(publicKey: string): string {
  const type = publicKey.trim().split(/\s+/)[0] ?? ''
  const names: Record<string, string> = {
    'ssh-ed25519': 'id_ed25519',
    'sk-ssh-ed25519@openssh.com': 'id_ed25519_sk',
    'ecdsa-sha2-nistp256': 'id_ecdsa',
    'ecdsa-sha2-nistp384': 'id_ecdsa',
    'sk-ecdsa-sha2-nistp256@openssh.com': 'id_ecdsa_sk',
    'ssh-rsa': 'id_rsa',
  }
  return names[type] ?? 'id'
}

/** A time span in its largest whole unit: "87 d", "5 h", "12 min". */
export function approxDuration(seconds: number, t: Translate): string {
  const total = Math.max(0, Math.round(seconds))
  if (total >= DAY_SECONDS) return t('ssh.duration.days', { count: Math.floor(total / DAY_SECONDS) })
  if (total >= 3600) return t('ssh.duration.hours', { count: Math.floor(total / 3600) })
  return t('ssh.duration.minutes', { count: Math.max(1, Math.floor(total / 60)) })
}
