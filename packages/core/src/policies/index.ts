import { AuthorizationError } from '../errors'
import { PolicySet } from './engine'

export type Role = 'admin' | 'operator' | 'viewer'

/**
 * Who is acting. API keys act as their owner, with the owner's role, so `id` is always
 * a user id; `api_key_id` says which key made the request, for the audit log.
 */
export interface Actor {
  id: string
  role: Role
  kind: 'session' | 'api_key' | 'cli'
  api_key_id?: string
  /** The command-line session the request came from, for `cli` actors. */
  cli_session_id?: string
  /** Client address, recorded in audit events. */
  ip?: string | null
  /**
   * When the person last proved who they are in this session, for step-up checks
   * (`assertStepUp`). Always null for API keys and command-line sessions, so they never pass one.
   */
  reauth_at: Date | null
}

const ROLE_RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 }

/** Whether the actor's role is at least `min`; admin > operator > viewer. */
export const hasRole = (actor: Actor, min: Role) => ROLE_RANK[actor.role] >= ROLE_RANK[min]

const isAdmin = (actor: Actor) => actor.role === 'admin'

interface UserSubject {
  id: string
  role: Role
}

export const userPolicy = new PolicySet<Actor, UserSubject, 'read' | 'update' | 'change_role' | 'deactivate' | 'reactivate' | 'set_username'>({
  read: (actor, user) => actor.id === user.id || isAdmin(actor),
  /** Name and preferences. */
  update: (actor, user) => actor.id === user.id || isAdmin(actor),
  /** Admins may also change their own role; the last admin is protected in core, not here. */
  change_role: isAdmin,
  deactivate: isAdmin,
  reactivate: isAdmin,
  /** The SSH username becomes a local login on hosts, so only admins choose it. */
  set_username: isAdmin,
})

/** Who may list every account, not only their own. */
export const peoplePolicy = new PolicySet<Actor, undefined, 'list' | 'search'>({
  list: isAdmin,
  /** Operators look people up by name to sign SSH certificates for them: active people, with name, email and username only. */
  search: (actor) => hasRole(actor, 'operator') && actor.kind !== 'cli',
})

export const invitePolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'revoke'>({
  read: isAdmin,
  create: isAdmin,
  revoke: isAdmin,
})

interface ApiKeySubject {
  user_id: string
}

/** Everyone manages their own keys. A key cannot mint another key, so a leaked one cannot spread. */
export const apiKeyPolicy = new PolicySet<Actor, ApiKeySubject, 'read' | 'create' | 'delete'>({
  read: (actor, key) => actor.id === key.user_id,
  create: (actor, key) => actor.kind === 'session' && actor.id === key.user_id,
  delete: (actor, key) => actor.id === key.user_id,
})

export const settingsPolicy = new PolicySet<Actor, undefined, 'read' | 'update'>({
  read: isAdmin,
  update: isAdmin,
})

/** The audit log: every signed-in role may read it; nobody may change it. */
export const auditPolicy = new PolicySet<Actor, undefined, 'read'>({
  read: (actor) => hasRole(actor, 'viewer'),
})

/**
 * Lifecycle actions on a certificate authority are for admins in an interactive session.
 * API keys never qualify, whatever their owner's role; core also requires a recent
 * re-authentication for each of them (`assertStepUp`).
 */
const canRunCaLifecycle = (actor: Actor) => isAdmin(actor) && actor.kind === 'session'

/**
 * Certificate authorities: every role reads them and their public material. Whether an action
 * fits the CA's current state (import only for externally signed CAs, for example) is checked
 * in core and reflected in the presenter's permissions, not here.
 */
export const caPolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'import' | 'renew' | 'disable' | 'revoke'>({
  read: (actor) => hasRole(actor, 'viewer'),
  create: canRunCaLifecycle,
  import: canRunCaLifecycle,
  renew: canRunCaLifecycle,
  disable: canRunCaLifecycle,
  revoke: canRunCaLifecycle,
})

/**
 * Templates: every role reads them. Changing one changes what certifly will sign, so it is for
 * admins in an interactive session; core also requires a recent re-authentication
 * (`assertStepUp`). API keys never qualify.
 */
export const templatePolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'update' | 'archive'>({
  read: (actor) => hasRole(actor, 'viewer'),
  create: canRunCaLifecycle,
  update: canRunCaLifecycle,
  archive: canRunCaLifecycle,
})

/**
 * Leaf certificates: every role reads them. Operators and admins issue and renew, also through
 * API keys, since that is what automation does; the template decides what may be issued. They
 * also revoke, with API keys too, so automation and emergencies need no interactive session, and
 * import certificates issued elsewhere into the inventory. `update` edits a certificate's tags,
 * which only sort and group the list, so it needs no step-up.
 */
export const certificatePolicy = new PolicySet<Actor, undefined, 'read' | 'issue' | 'renew' | 'revoke' | 'import' | 'update'>({
  read: (actor) => hasRole(actor, 'viewer'),
  update: (actor) => hasRole(actor, 'operator'),
  issue: (actor) => hasRole(actor, 'operator'),
  renew: (actor) => hasRole(actor, 'operator'),
  revoke: (actor) => hasRole(actor, 'operator'),
  import: (actor) => hasRole(actor, 'operator'),
})

/**
 * Tags: every role reads the list. Admins keep it, like other instance configuration, in an
 * interactive session; core also requires a recent re-authentication. API keys never qualify.
 */
export const tagPolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'update' | 'delete'>({
  read: (actor) => hasRole(actor, 'viewer'),
  create: canRunCaLifecycle,
  update: canRunCaLifecycle,
  delete: canRunCaLifecycle,
})

/**
 * Trust bundles: every role reads them (their PEM is public anyway). What goes into a client's
 * trust store is a CA-level decision, so changing one is for admins in an interactive session;
 * core also requires a recent re-authentication. API keys never qualify.
 */
export const trustBundlePolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'update' | 'delete'>({
  read: (actor) => hasRole(actor, 'viewer'),
  create: canRunCaLifecycle,
  update: canRunCaLifecycle,
  delete: canRunCaLifecycle,
})

/**
 * Alerts: channels hold webhook secrets and recipient lists, and rules decide who hears about
 * what, so admins manage them, in an interactive session with a recent re-authentication.
 * Operators may read the delivery history: they act on expiring certificates and should see
 * whether a warning went out. It shows channel names and errors, never channel settings.
 */
export const alertPolicy = new PolicySet<Actor, undefined, 'read' | 'manage' | 'read_deliveries'>({
  read: isAdmin,
  manage: canRunCaLifecycle,
  read_deliveries: (actor) => hasRole(actor, 'operator'),
})

/**
 * SSH certificate authorities: every role reads them (their public key is public anyway).
 * Creating, importing, changing and deleting one is for admins in an interactive session; core
 * also requires a recent re-authentication for creating and importing. API keys and
 * command-line sessions never qualify.
 */
export const sshCaPolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'import' | 'update' | 'delete'>({
  read: (actor) => hasRole(actor, 'viewer'),
  create: canRunCaLifecycle,
  import: canRunCaLifecycle,
  update: canRunCaLifecycle,
  delete: canRunCaLifecycle,
})

/**
 * SSH host groups: operators read them to add hosts. They decide which names hosts may be
 * trusted for and how user certificates look, so changing one is for admins in an interactive
 * session; core also requires a recent re-authentication. API keys never qualify.
 */
export const sshHostGroupPolicy = new PolicySet<Actor, undefined, 'read' | 'manage'>({
  read: (actor) => hasRole(actor, 'operator'),
  manage: canRunCaLifecycle,
})

/**
 * Groups of people and the SSH access rules built on them: admins read them. They decide who
 * may log in where, so changing them takes an interactive session; core also requires a recent
 * re-authentication. API keys never qualify.
 */
export const sshAccessPolicy = new PolicySet<Actor, undefined, 'read' | 'manage'>({
  read: (actor) => isAdmin(actor) && actor.kind !== 'cli',
  manage: canRunCaLifecycle,
})

/** Join tokens enrol hosts into the SSH trust. Admins in an interactive session create and list them. */
export const sshJoinTokenPolicy = new PolicySet<Actor, undefined, 'read' | 'create' | 'delete'>({
  read: canRunCaLifecycle,
  create: canRunCaLifecycle,
  delete: canRunCaLifecycle,
})

/** The registry of SSH hosts: operators and admins, also with API keys. */
export const sshHostPolicy = new PolicySet<Actor, undefined, 'read' | 'manage'>({
  read: (actor) => hasRole(actor, 'operator') && actor.kind !== 'cli',
  manage: (actor) => hasRole(actor, 'operator') && actor.kind !== 'cli',
})

interface SshCertificateSubject {
  user_id: string | null
  kind?: 'user' | 'host'
}

/**
 * SSH certificates. Everyone reads and revokes their own user certificates; operators and
 * admins read and revoke every user certificate and every host certificate. Signing for
 * someone else is for admins in an interactive session (core also requires a recent
 * re-authentication): the certificate lets them log in as that person. What it may contain is
 * decided by the target's access rules, in core.
 */
export const sshCertificatePolicy = new PolicySet<Actor, SshCertificateSubject | undefined, 'read' | 'revoke' | 'sign_for_others'>({
  read: (actor, cert) => !cert || (cert.kind === 'user' && cert.user_id === actor.id) || hasRole(actor, 'operator'),
  revoke: (actor, cert) => (cert?.kind === 'user' && cert.user_id === actor.id) || hasRole(actor, 'operator'),
  sign_for_others: canRunCaLifecycle,
})

interface SshSecurityKeySubject {
  user_id: string
}

/**
 * Registered security keys. People read, rename and revoke their own; admins read and revoke
 * anyone's. API keys do none of it, so a leaked key cannot unregister a YubiKey or learn which
 * ones exist. Registering is not here: only the person's own browser session approves a key.
 */
export const sshSecurityKeyPolicy = new PolicySet<Actor, SshSecurityKeySubject, 'read' | 'update' | 'revoke'>({
  read: (actor, key) => actor.kind !== 'api_key' && (key.user_id === actor.id || isAdmin(actor)),
  update: (actor, key) => actor.kind !== 'api_key' && key.user_id === actor.id,
  revoke: (actor, key) => actor.kind !== 'api_key' && (key.user_id === actor.id || isAdmin(actor)),
})

/** Throw a 403 unless the policy allows the action. */
export function authorize<A, S, Action extends string>(
  policy: PolicySet<A, S, Action>,
  actor: A,
  action: Action,
  subject: S,
): void {
  if (!policy.can(actor, action, subject)) throw new AuthorizationError()
}
