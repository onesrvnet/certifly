import type {
  CertificateAuthority,
  ExtendedKeyUsage,
  KeyAlgorithm,
  LeafKeyUsage,
  SanType,
  SubjectField,
  Template,
  TemplatePreset,
  TemplateSettingsInput,
} from '~/types/api'

/** The extended key usages a template can give its certificates, in the order the form lists them. */
export const LEAF_EXTENDED_KEY_USAGES: ExtendedKeyUsage[] = ['server_auth', 'client_auth', 'code_signing', 'email_protection', 'time_stamping', 'ocsp_signing']
export const SAN_TYPES: SanType[] = ['dns', 'ip', 'email', 'uri']
export const SUBJECT_FIELDS: SubjectField[] = ['CN', 'O', 'OU', 'C', 'ST', 'L', 'E']
/** Fields a template may fill in itself; the common name always comes from the request. */
export const DEFAULTABLE_FIELDS: SubjectField[] = ['O', 'OU', 'C', 'ST', 'L', 'E']
export const LEAF_KEY_ALGORITHMS: KeyAlgorithm[] = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096']
export const LEAF_KEY_USAGES: LeafKeyUsage[] = ['digital_signature', 'key_encipherment', 'key_agreement', 'non_repudiation', 'data_encipherment']
export const RSA_ONLY_USAGES: LeafKeyUsage[] = ['key_encipherment', 'data_encipherment']

/** The cards of the template form, in order; the section nav links to them. */
export const TEMPLATE_FORM_SECTIONS = ['template', 'purpose', 'names', 'subject', 'keys', 'lifetime'] as const
export type TemplateFormSection = (typeof TEMPLATE_FORM_SECTIONS)[number]
export const templateSectionId = (section: TemplateFormSection) => `tpl-section-${section}`

/** What the template form edits, lifetimes in days. */
export interface TemplateFormState {
  name: string
  slug: string
  description: string
  ca_id: string
  extended_key_usages: ExtendedKeyUsage[]
  tag_ids: string[]
  allowed_san_types: SanType[]
  allowed_dns: string[]
  allowed_ips: string[]
  allow_wildcards: boolean
  require_san: boolean
  require_common_name: boolean
  subject_defaults: Record<string, string>
  allowed_subject_fields: SubjectField[]
  key_algorithms: KeyAlgorithm[]
  max_ttl_days: number
  default_ttl_days: number
  key_usages: LeafKeyUsage[]
  allow_server_keygen: boolean
  renew_before_days: number
}

type Source = Pick<
  TemplatePreset,
  | 'extended_key_usages'
  | 'allowed_san_types'
  | 'allowed_dns'
  | 'allowed_ips'
  | 'allow_wildcards'
  | 'require_san'
  | 'require_common_name'
  | 'subject_defaults'
  | 'allowed_subject_fields'
  | 'key_algorithms'
  | 'max_ttl_seconds'
  | 'default_ttl_seconds'
  | 'key_usages'
  | 'allow_server_keygen'
  | 'renew_before_days'
>

function fromSettings(source: Source): Omit<TemplateFormState, 'name' | 'slug' | 'description' | 'ca_id' | 'tag_ids'> {
  return {
    extended_key_usages: [...source.extended_key_usages] as ExtendedKeyUsage[],
    allowed_san_types: [...source.allowed_san_types] as SanType[],
    allowed_dns: [...source.allowed_dns],
    allowed_ips: [...source.allowed_ips],
    allow_wildcards: source.allow_wildcards,
    require_san: source.require_san,
    require_common_name: source.require_common_name,
    subject_defaults: { ...(source.subject_defaults as Record<string, string>) },
    allowed_subject_fields: [...source.allowed_subject_fields] as SubjectField[],
    key_algorithms: [...source.key_algorithms] as KeyAlgorithm[],
    max_ttl_days: secondsToDays(source.max_ttl_seconds),
    default_ttl_days: secondsToDays(source.default_ttl_seconds),
    key_usages: [...source.key_usages] as LeafKeyUsage[],
    allow_server_keygen: source.allow_server_keygen,
    renew_before_days: source.renew_before_days,
  }
}

export function formFromPreset(preset: TemplatePreset, name: string): TemplateFormState {
  return { name, slug: '', description: '', ca_id: '', tag_ids: [], ...fromSettings(preset) }
}

export function formFromTemplate(template: Template): TemplateFormState {
  return { name: template.name, slug: template.slug, description: template.description, ca_id: template.ca_id, tag_ids: template.tags.map((tag) => tag.id), ...fromSettings(template) }
}

/** The settings as the API takes them. The protocol flags are left as they are: this form does not edit them yet. */
export function settingsFromForm(form: TemplateFormState): Omit<TemplateSettingsInput, 'allow_acme' | 'allow_est'> {
  const defaults = Object.fromEntries(Object.entries(form.subject_defaults).filter(([, value]) => value.trim()).map(([field, value]) => [field, value.trim()]))
  return {
    allowed_san_types: form.allowed_san_types,
    allowed_dns: form.allowed_dns,
    allowed_ips: form.allowed_san_types.includes('ip') ? form.allowed_ips : [],
    allow_wildcards: form.allow_wildcards,
    require_san: form.require_san,
    require_common_name: form.require_common_name,
    subject_defaults: defaults,
    allowed_subject_fields: form.allowed_subject_fields,
    key_algorithms: form.key_algorithms,
    max_ttl_seconds: daysToSeconds(form.max_ttl_days),
    default_ttl_seconds: daysToSeconds(form.default_ttl_days),
    key_usages: form.key_usages,
    extended_key_usages: form.extended_key_usages,
    allow_server_keygen: form.allow_server_keygen,
    renew_before_days: form.renew_before_days,
  }
}

/** The form field a server refusal belongs to, so the message shows next to it. */
const FIELD_OF_CODE: Record<string, string> = {
  invalid_slug: 'slug',
  slug_taken: 'slug',
  template_slug_taken: 'slug',
  ca_disabled: 'ca_id',
  ca_not_active: 'ca_id',
  ca_not_found: 'ca_id',
  invalid_extended_key_usages: 'extended_key_usages',
  invalid_key_usages: 'key_usages',
  san_types_required: 'allowed_san_types',
  invalid_domain_pattern: 'allowed_dns',
  allowed_dns_required: 'allowed_dns',
  invalid_cidr: 'allowed_ips',
  allowed_ips_required: 'allowed_ips',
  invalid_subject_defaults: 'subject',
  common_name_not_allowed: 'subject',
  unsupported_key: 'key_algorithms',
  invalid_ttl: 'ttl',
}

export interface TemplateFormErrors {
  fields: Record<string, string>
  /** Rules the server marked, to highlight on their chips. */
  problems: string[]
}

/** Field messages for a refusal of `templates.create` or `templates.update`. */
export function templateFormErrors(error: RpcError, message: string): TemplateFormErrors {
  const fields: Record<string, string> = {}
  let problems: string[] = []
  if (error.code === 'template_outside_name_constraints') {
    const list = (error.details?.problems ?? []) as { rule: string; type: 'dns' | 'ip' }[]
    problems = list.map((p) => p.rule)
    for (const type of ['dns', 'ip'] as const) {
      const rules = list.filter((p) => p.type === type).map((p) => p.rule)
      if (rules.length) fields[type === 'dns' ? 'allowed_dns' : 'allowed_ips'] = `${message} ${rules.join(', ')}`
    }
  } else if (error.code === 'invalid_domain_pattern' || error.code === 'invalid_cidr') {
    problems = (error.details?.invalid ?? []) as string[]
    fields[FIELD_OF_CODE[error.code]!] = `${message} ${problems.join(', ')}`
  } else if (FIELD_OF_CODE[error.code]) fields[FIELD_OF_CODE[error.code]!] = message
  return { fields, problems }
}

/** CAs a template can be bound to: those that can sign now. */
export const bindableCas = (cas: readonly CertificateAuthority[]) => cas.filter((ca) => ca.status === 'active')
