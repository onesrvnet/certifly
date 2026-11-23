<script setup lang="ts">
import { TagIcon, TriangleAlertIcon } from '@lucide/vue'

import type { CertificateAuthority, ExtendedKeyUsage, KeyAlgorithm, LeafKeyUsage, SanType, SubjectField, Tag } from '~/types/api'

/**
 * Every setting of a template, grouped as an admin thinks about them: which CA signs, what the
 * certificate is for, which names it may carry, the subject, keys and lifetimes. Messages for
 * fields the server refused show next to those fields.
 */
const form = defineModel<TemplateFormState>({ required: true })
const props = defineProps<{
  cas: CertificateAuthority[]
  mode: 'create' | 'edit'
  errors?: TemplateFormErrors
  disabled?: boolean
  tags?: Tag[]
}>()
const { t, d } = useI18n()

const error = (field: string) => props.errors?.fields[field]
const ca = computed(() => props.cas.find((c) => c.id === form.value.ca_id) ?? null)
const caDaysLeft = computed(() => (ca.value?.not_after ? Math.floor((new Date(ca.value.not_after).getTime() - Date.now()) / (DAY_SECONDS * 1000)) : null))
const exceedsCa = computed(() => caDaysLeft.value !== null && form.value.max_ttl_days > caDaysLeft.value)

function toggle<T>(list: T[], value: T, on: boolean | 'indeterminate'): T[] {
  return on === true ? (list.includes(value) ? list : [...list, value]) : list.filter((v) => v !== value)
}
const setSanType = (type: SanType, on: boolean | 'indeterminate') => (form.value.allowed_san_types = toggle(form.value.allowed_san_types, type, on))
const setField = (field: SubjectField, on: boolean | 'indeterminate') => (form.value.allowed_subject_fields = toggle(form.value.allowed_subject_fields, field, on))
const setAlgorithm = (algorithm: KeyAlgorithm, on: boolean | 'indeterminate') => (form.value.key_algorithms = toggle(form.value.key_algorithms, algorithm, on))
const setEku = (eku: ExtendedKeyUsage, on: boolean | 'indeterminate') => (form.value.extended_key_usages = toggle(form.value.extended_key_usages, eku, on))
const defaultTags = computed(() => (props.tags ?? []).filter((tag) => form.value.tag_ids.includes(tag.id)))
const setUsage = (usage: LeafKeyUsage, on: boolean | 'indeterminate') => (form.value.key_usages = toggle(form.value.key_usages, usage, on))

// The slug follows the name on create until someone edits it.
const slugEdited = ref(false)
watch(
  () => form.value.name,
  (name) => {
    if (props.mode === 'create' && !slugEdited.value) form.value.slug = slugify(name)
  },
  // Also for the name a preset fills in.
  { immediate: true },
)

// After a refused save, bring the first problem into view: the message sits next to its field,
// which may be far above the save button.
const root = useTemplateRef<HTMLElement>('root')
watch(
  () => props.errors,
  async (errors) => {
    if (!errors || (!Object.keys(errors.fields ?? {}).length && !errors.problems?.length)) return
    await nextTick()
    root.value?.querySelector('[data-invalid="true"], [role="alert"]')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  },
)
// A required common name must be one the requester may set.
watch(
  () => form.value.require_common_name,
  (required) => {
    if (required && !form.value.allowed_subject_fields.includes('CN')) form.value.allowed_subject_fields = ['CN', ...form.value.allowed_subject_fields]
  },
)
</script>

<template>
  <div ref="root" class="flex flex-col gap-6">
    <FormCard :id="templateSectionId('template')" class="scroll-mt-20" :title="t('templates.form.sections.template')">
      <FieldGroup>
        <Field>
          <FieldLabel for="tpl-name">{{ t('templates.form.name') }}</FieldLabel>
          <Input id="tpl-name" v-model="form.name" maxlength="100" required :disabled="disabled" :placeholder="t('templates.form.namePlaceholder')" />
        </Field>
        <Field :data-invalid="!!error('slug') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel for="tpl-slug">{{ t('templates.form.slug') }}</FieldLabel>
            <InfoTip :text="t('templates.form.slugHint')" />
          </div>
          <Input id="tpl-slug" v-model="form.slug" maxlength="64" required :disabled="disabled || mode === 'edit'" pattern="[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?" class="font-mono" @input="slugEdited = true" />
          <FieldError v-if="error('slug')">{{ error('slug') }}</FieldError>
        </Field>
        <Field>
          <FieldLabel for="tpl-description">{{ t('templates.form.description') }}</FieldLabel>
          <Textarea id="tpl-description" v-model="form.description" rows="2" maxlength="1000" :disabled="disabled" />
        </Field>
        <Field :data-invalid="!!error('ca_id') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel for="tpl-ca">{{ t('templates.form.ca') }}</FieldLabel>
            <InfoTip v-if="ca?.not_after" :text="t('templates.form.caHint', { date: d(new Date(ca.not_after), { dateStyle: 'medium' }) })" />
          </div>
          <p v-if="!cas.length" class="text-sm text-muted-foreground">{{ t('templates.form.noCas') }}</p>
          <Select v-else v-model="form.ca_id" :disabled="disabled">
            <SelectTrigger id="tpl-ca" class="w-full"><SelectValue :placeholder="t('templates.form.caPlaceholder')" /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="option in cas" :key="option.id" :value="option.id">
                {{ option.name }}<span v-if="option.signing === 'self_signed'" class="text-muted-foreground"> ({{ t('templates.rootCa') }})</span>
              </SelectItem>
            </SelectContent>
          </Select>
          <FieldError v-if="error('ca_id')">{{ error('ca_id') }}</FieldError>
        </Field>
        <Field v-if="tags">
          <div class="flex items-center gap-1.5">
            <FieldLabel>{{ t('templates.form.defaultTags') }}</FieldLabel>
            <InfoTip :text="t('templates.form.defaultTagsHint')" />
          </div>
          <div class="flex flex-wrap items-center gap-1.5">
            <TagChip v-for="tag in defaultTags" :key="tag.id" :name="tag.name" :color="tag.color" />
            <TagPicker v-if="!disabled" v-model="form.tag_ids" :tags="tags">
              <Button type="button" variant="outline" size="sm"><TagIcon />{{ t('tags.editTags') }}</Button>
            </TagPicker>
            <span v-else-if="!defaultTags.length" class="text-sm text-muted-foreground">{{ t('tags.none') }}</span>
          </div>
        </Field>
        <Alert v-if="ca?.signing === 'self_signed'" class="border-warning/40 bg-warning-soft text-warning">
          <TriangleAlertIcon />
          <AlertTitle>{{ t('templates.rootWarningTitle') }}</AlertTitle>
          <AlertDescription class="text-foreground">{{ t('templates.rootWarning') }}</AlertDescription>
        </Alert>
        <div v-if="ca?.name_constraints" class="flex flex-col gap-2 rounded-md border bg-muted/30 p-3">
          <div class="flex items-center gap-1.5">
            <span class="text-sm font-medium">{{ t('templates.form.caConstraints') }}</span>
            <InfoTip :text="t('templates.form.caConstraintsHint')" />
          </div>
          <CaNameConstraintsView :constraints="ca.name_constraints" />
        </div>
      </FieldGroup>
    </FormCard>

    <FormCard :id="templateSectionId('purpose')" class="scroll-mt-20" :title="t('templates.form.sections.purpose')">
      <FieldGroup>
        <Field :data-invalid="!!error('extended_key_usages') || undefined">
          <FieldLabel>{{ t('templates.form.extendedKeyUsages') }}</FieldLabel>
          <div class="grid gap-2 sm:grid-cols-2">
            <Label v-for="eku in LEAF_EXTENDED_KEY_USAGES" :key="eku" class="font-normal">
              <Checkbox :model-value="form.extended_key_usages.includes(eku)" :disabled="disabled" @update:model-value="setEku(eku, $event)" />
              {{ t(`certificates.eku.${eku}`) }}
            </Label>
          </div>
          <FieldError v-if="error('extended_key_usages')">{{ error('extended_key_usages') }}</FieldError>
        </Field>
        <Field :data-invalid="!!error('key_usages') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel>{{ t('templates.form.keyUsages') }}</FieldLabel>
            <InfoTip :text="t('templates.form.rsaOnlyHint')" />
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <Label v-for="usage in LEAF_KEY_USAGES" :key="usage" class="font-normal">
              <Checkbox :model-value="form.key_usages.includes(usage)" :disabled="disabled" @update:model-value="setUsage(usage, $event)" />
              {{ t(`certificates.ku.${usage}`) }}
              <span v-if="RSA_ONLY_USAGES.includes(usage)" class="text-xs text-muted-foreground">{{ t('templates.form.rsaOnly') }}</span>
            </Label>
          </div>
          <FieldError v-if="error('key_usages')">{{ error('key_usages') }}</FieldError>
        </Field>
      </FieldGroup>
    </FormCard>

    <FormCard :id="templateSectionId('names')" class="scroll-mt-20" :title="t('templates.form.sections.names')" :info="t('templates.form.namesHint')">
      <FieldGroup>
        <Field :data-invalid="!!error('allowed_san_types') || undefined">
          <FieldLabel>{{ t('templates.form.sanTypes') }}</FieldLabel>
          <div class="flex flex-wrap gap-x-5 gap-y-2">
            <Label v-for="type in SAN_TYPES" :key="type" class="font-normal">
              <Checkbox :model-value="form.allowed_san_types.includes(type)" :disabled="disabled" @update:model-value="setSanType(type, $event)" />
              {{ t(`certificates.sanTypes.${type}`) }}
            </Label>
          </div>
          <FieldError v-if="error('allowed_san_types')">{{ error('allowed_san_types') }}</FieldError>
        </Field>
        <TemplateRuleList
          id="tpl-dns"
          v-model="form.allowed_dns"
          kind="pattern"
          :label="t('templates.form.allowedDns')"
          :placeholder="t('templates.form.allowedDnsPlaceholder')"
          :info="t('templates.form.allowedDnsHint')"
          :error="error('allowed_dns')"
          :problems="errors?.problems"
          :disabled="disabled"
        />
        <TemplateRuleList
          v-if="form.allowed_san_types.includes('ip')"
          id="tpl-ips"
          v-model="form.allowed_ips"
          kind="cidr"
          :label="t('templates.form.allowedIps')"
          :placeholder="t('templates.form.allowedIpsPlaceholder')"
          :error="error('allowed_ips')"
          :problems="errors?.problems"
          :disabled="disabled"
        />
        <Field orientation="horizontal">
          <Switch id="tpl-wildcards" v-model="form.allow_wildcards" :disabled="disabled" />
          <FieldContent>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="tpl-wildcards">{{ t('templates.form.allowWildcards') }}</FieldLabel>
              <InfoTip :text="t('templates.form.allowWildcardsHint')" />
            </div>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <Switch id="tpl-require-san" v-model="form.require_san" :disabled="disabled" />
          <FieldContent>
            <FieldLabel for="tpl-require-san">{{ t('templates.form.requireSan') }}</FieldLabel>
          </FieldContent>
        </Field>
      </FieldGroup>
    </FormCard>

    <FormCard :id="templateSectionId('subject')" class="scroll-mt-20" :title="t('templates.form.sections.subject')">
      <FieldGroup>
        <Field orientation="horizontal">
          <Switch id="tpl-require-cn" v-model="form.require_common_name" :disabled="disabled" />
          <FieldContent>
            <FieldLabel for="tpl-require-cn">{{ t('templates.form.requireCommonName') }}</FieldLabel>
          </FieldContent>
        </Field>
        <Field :data-invalid="!!error('subject') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel>{{ t('templates.form.allowedSubjectFields') }}</FieldLabel>
            <InfoTip :text="t('templates.form.subjectHint')" />
          </div>
          <div class="flex flex-wrap gap-x-5 gap-y-2">
            <Label v-for="field in SUBJECT_FIELDS" :key="field" class="font-normal">
              <Checkbox :model-value="form.allowed_subject_fields.includes(field)" :disabled="disabled" @update:model-value="setField(field, $event)" />
              {{ t(`templates.subjectFields.${field}`) }}
            </Label>
          </div>
          <FieldError v-if="error('subject')">{{ error('subject') }}</FieldError>
        </Field>
        <div class="grid gap-4 sm:grid-cols-2">
          <Field v-for="field in DEFAULTABLE_FIELDS" :key="field">
            <FieldLabel :for="`tpl-default-${field}`">{{ t('templates.form.defaultFor', { field: t(`templates.subjectFields.${field}`) }) }}</FieldLabel>
            <Input :id="`tpl-default-${field}`" v-model="form.subject_defaults[field]" :maxlength="field === 'C' ? 2 : 64" :disabled="disabled" />
          </Field>
        </div>
      </FieldGroup>
    </FormCard>

    <FormCard :id="templateSectionId('keys')" class="scroll-mt-20" :title="t('templates.form.sections.keys')">
      <FieldGroup>
        <Field :data-invalid="!!error('key_algorithms') || undefined">
          <FieldLabel>{{ t('templates.form.keyAlgorithms') }}</FieldLabel>
          <div class="grid gap-2 sm:grid-cols-2">
            <Label v-for="algorithm in LEAF_KEY_ALGORITHMS" :key="algorithm" class="font-normal">
              <Checkbox :model-value="form.key_algorithms.includes(algorithm)" :disabled="disabled" @update:model-value="setAlgorithm(algorithm, $event)" />
              {{ t(`cas.algorithms.${algorithm}`) }}
            </Label>
          </div>
          <FieldError v-if="error('key_algorithms')">{{ error('key_algorithms') }}</FieldError>
        </Field>
        <Field orientation="horizontal">
          <Switch id="tpl-keygen" v-model="form.allow_server_keygen" :disabled="disabled" />
          <FieldContent>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="tpl-keygen">{{ t('templates.form.allowKeygen') }}</FieldLabel>
              <InfoTip :text="t('templates.form.allowKeygenHint')" />
            </div>
          </FieldContent>
        </Field>
      </FieldGroup>
    </FormCard>

    <FormCard :id="templateSectionId('lifetime')" class="scroll-mt-20" :title="t('templates.form.sections.lifetime')">
      <FieldGroup class="grid gap-4 sm:grid-cols-3">
        <Field :data-invalid="!!error('ttl') || undefined">
          <FieldLabel for="tpl-default-ttl">{{ t('templates.form.defaultTtl') }}</FieldLabel>
          <Input id="tpl-default-ttl" v-model.number="form.default_ttl_days" type="number" min="1" :max="form.max_ttl_days" required :disabled="disabled" />
        </Field>
        <Field :data-invalid="!!error('ttl') || undefined">
          <FieldLabel for="tpl-max-ttl">{{ t('templates.form.maxTtl') }}</FieldLabel>
          <Input id="tpl-max-ttl" v-model.number="form.max_ttl_days" type="number" min="1" max="3650" required :disabled="disabled" />
        </Field>
        <Field>
          <FieldLabel for="tpl-renew">{{ t('templates.form.renewBefore') }}</FieldLabel>
          <Input id="tpl-renew" v-model.number="form.renew_before_days" type="number" min="0" max="365" required :disabled="disabled" />
        </Field>
        <FieldError v-if="error('ttl')" class="sm:col-span-3">{{ error('ttl') }}</FieldError>
        <FieldDescription v-if="exceedsCa" class="text-warning sm:col-span-3">{{ t('templates.ttlExceedsCa', { days: caDaysLeft }) }}</FieldDescription>
      </FieldGroup>
    </FormCard>
  </div>
</template>
