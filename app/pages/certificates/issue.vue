<script setup lang="ts">
import { CircleCheckIcon, InfoIcon, TagIcon } from '@lucide/vue'
import { useEventListener } from '@vueuse/core'

import type { IssueResult, LeafKeyUsage, SanInput, Tag, Template } from '~/types/api'

/**
 * Issue a certificate: pick a template, bring a CSR or let certifly generate the key, set the
 * names and lifetime. The result shows the downloads and, for a generated key, the private key
 * once; it is dropped from this page's state as soon as the person moves on.
 */
definePageMeta({ titleKey: 'certificates.issue.title', requires: ['instance', 'issue_certificate'] })

const { t, d } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const errorMessage = useErrorMessage()

useHead({ title: () => t('certificates.issue.title') })

const { data: templates } = await useAsyncData(
  'issue-templates',
  async () => (await rpc('templates.list', { status: 'active', limit: 200 })).data.filter((tpl) => tpl.permissions.issue),
  { default: () => [] as Template[] },
)

const { data: allTags } = await useAsyncData('issue-tags', async () => (await rpc('tags.list')).data, { default: () => [] as Tag[] })

const templateId = ref(typeof route.query.template === 'string' ? route.query.template : '')
const template = computed(() => templates.value.find((tpl) => tpl.id === templateId.value) ?? null)
if (!template.value && templates.value.length === 1) templateId.value = templates.value[0]!.id

const commonName = ref('')
const sans = ref<SanInput[]>([])
const ttlDays = ref(30)
const key = ref<KeySourceState>(emptyKeySource('keygen'))
/** Starts as the template's default tags; the operator can change them before issuing. */
const tagIds = ref<string[]>([])
const pickedTags = computed(() => allTags.value.filter((tag) => tagIds.value.includes(tag.id)))

// A new template brings its own defaults: lifetime, SAN types, whether certifly may make the key.
watch(
  template,
  (value) => {
    if (!value) return
    ttlDays.value = secondsToDays(value.default_ttl_seconds)
    tagIds.value = value.tags.map((tag) => tag.id)
    // certifly making the key is the default wherever the template allows it; a CSR is the fallback.
    key.value.mode = value.allow_server_keygen ? 'keygen' : 'csr'
    sans.value = sans.value.filter((san) => value.allowed_san_types.includes(san.type))
    if (!sans.value.length && value.allowed_san_types.length && key.value.mode !== 'csr') sans.value = [{ type: value.allowed_san_types[0]!, value: '' }]
  },
  { immediate: true },
)

// Without a CSR the names must be typed in; start with an empty row.
watch(
  () => key.value.mode,
  (mode) => {
    const types = template.value?.allowed_san_types ?? []
    if (mode === 'keygen' && !sans.value.length && types.length) sans.value = [{ type: types[0]!, value: '' }]
  },
)

const maxDays = computed(() => (template.value ? Math.floor(template.value.max_ttl_seconds / DAY_SECONDS) : 3650))
// Facts about the chosen template, shown under the picker.
const allowedNames = computed(() => (template.value ? [...template.value.allowed_dns, ...template.value.allowed_ips].join(', ') : ''))
// Mirrors the server: key and data encipherment are only set for RSA keys. A CSR's key type is
// unknown until the server parses it, so those usages are marked instead of dropped.
const keyUsages = computed(() => {
  const rsa = key.value.mode === 'keygen' ? key.value.algorithm.startsWith('rsa') : null
  return (template.value?.key_usages ?? [])
    .map((usage) => ({ usage, rsaOnly: RSA_ONLY_USAGES.includes(usage as LeafKeyUsage) }))
    .filter((entry) => rsa !== false || !entry.rsaOnly)
    .map((entry) => ({ usage: entry.usage, rsaOnly: entry.rsaOnly && rsa === null }))
})
const cnAllowed = computed(() => template.value?.allowed_subject_fields.includes('CN') ?? false)
const filledSans = computed(() => sans.value.filter((san) => san.value.trim()).map((san) => ({ type: san.type, value: san.value.trim() })))
const ready = computed(
  () =>
    !!template.value &&
    keySourceReady(key.value) &&
    ttlDays.value >= 1 &&
    (!template.value.require_common_name || !!commonName.value.trim()) &&
    // With a CSR the SANs may come from it; otherwise a required SAN must be typed in.
    (key.value.mode === 'csr' || !template.value.require_san || filledSans.value.length > 0),
)

const formError = ref('')
const invalidSans = ref<string[]>([])
const result = ref<IssueResult | null>(null)

const submit = useAction(async () => {
  if (!template.value) return
  formError.value = ''
  invalidSans.value = []
  try {
    const res = await rpc('certificates.issue', {
      template_id: template.value.id,
      ...keySourceRequest(key.value),
      ...(commonName.value.trim() ? { common_name: commonName.value.trim() } : {}),
      // With a CSR, no SANs typed in means "take the CSR's".
      ...(filledSans.value.length || key.value.mode !== 'csr' ? { sans: filledSans.value } : {}),
      ttl_seconds: daysToSeconds(ttlDays.value),
      tag_ids: tagIds.value,
    })
    result.value = res.data
    // The password has done its job; do not keep it around either.
    key.value = { ...key.value, password: '', confirm: '' }
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    const violations = (error.details?.violations ?? []) as { san: string }[]
    invalidSans.value = violations.map((v) => v.san)
    formError.value = violations.length ? `${errorMessage(error)} ${invalidSans.value.join(', ')}` : errorMessage(error)
  }
})

const fileName = computed(() => certificateFileName(result.value?.certificate.common_name ?? result.value?.certificate.sans[0]?.value))

/** Forget the result, and with it the one-time private key. */
function clear() {
  result.value = null
}

function another() {
  clear()
  commonName.value = ''
  sans.value = []
  key.value = emptyKeySource(key.value.mode, key.value.algorithm)
}

async function open() {
  const id = result.value?.certificate.id
  clear()
  if (id) await router.push(`/certificates/${id}`)
}

// Closing the tab or reloading also loses the key; let the browser ask first.
useEventListener(import.meta.client ? window : undefined, 'beforeunload', (event: BeforeUnloadEvent) => {
  if (result.value?.private_key) event.preventDefault()
})
onBeforeRouteLeave(() => {
  if (result.value?.private_key && !window.confirm(t('certificates.privateKey.leaveConfirm'))) return false
  clear()
})
onBeforeUnmount(clear)
</script>

<template>
  <div class="mx-auto flex w-full max-w-3xl flex-col gap-8 p-4 md:p-10">
    <section v-if="result" class="flex flex-col gap-6">
      <div class="flex items-start gap-3">
        <CircleCheckIcon class="mt-1 size-6 shrink-0 text-success" />
        <div class="flex min-w-0 flex-col gap-1">
          <h2 class="text-xl font-semibold tracking-tight break-words">{{ t('certificates.issue.issued', { name: result.certificate.common_name ?? result.certificate.sans[0]?.value ?? '' }) }}</h2>
          <p class="text-sm text-muted-foreground">
            {{ t('certificates.issue.validUntil', { date: d(new Date(result.certificate.not_after), { dateStyle: 'medium', timeStyle: 'short' }) }) }}
          </p>
        </div>
      </div>

      <Alert v-if="result.not_after_clamped" class="border-warning/40 bg-warning-soft text-warning">
        <InfoIcon />
        <AlertDescription class="text-foreground">{{ t('certificates.issue.clamped') }}</AlertDescription>
      </Alert>
      <Alert v-if="result.ignored_subject_fields.length">
        <InfoIcon />
        <AlertDescription>{{ t('certificates.issue.ignoredFields', { fields: result.ignored_subject_fields.join(', ') }) }}</AlertDescription>
      </Alert>

      <CertPrivateKeyPanel v-if="result.private_key" :private-key="result.private_key" :file-name="fileName" />

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('certificates.downloads.title') }}</CardTitle>
            <InfoTip :text="t('certificates.downloads.hint')" />
          </div>
        </CardHeader>
        <CardContent>
          <CertDownloads :certificate="result.certificate" :file-name="fileName" />
        </CardContent>
      </Card>

      <div class="flex flex-wrap justify-end gap-2">
        <Button variant="outline" @click="another">{{ t('certificates.issue.another') }}</Button>
        <Button @click="open">{{ t('certificates.issue.open') }}</Button>
      </div>
    </section>

    <form v-else class="flex flex-col gap-6" @submit.prevent="submit()">
      <FormCard :step="1" :title="t('certificates.issue.template')">
        <FieldGroup>
          <Field>
            <FieldLabel for="issue-template">{{ t('certificates.issue.template') }}</FieldLabel>
            <p v-if="!templates.length" class="text-sm text-muted-foreground">{{ t('certificates.issue.noTemplates') }}</p>
            <Select v-else v-model="templateId">
              <SelectTrigger id="issue-template" class="w-full"><SelectValue :placeholder="t('certificates.issue.templatePlaceholder')" /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="option in templates" :key="option.id" :value="option.id">{{ option.name }} ({{ t('certificates.issue.caInOption', { ca: option.ca.name }) }})</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <template v-if="template">
            <div class="flex flex-wrap gap-2">
              <MetaChip :label="t('certificates.detail.issuingCa')">{{ template.ca.name }}</MetaChip>
              <MetaChip v-if="allowedNames" :label="t('certificates.issue.allowedNames')" :title="allowedNames"><span class="font-mono">{{ allowedNames }}</span></MetaChip>
            </div>
            <div class="flex flex-col gap-2">
              <div v-if="keyUsages.length" class="flex flex-wrap items-center gap-1.5">
                <span class="mr-1 text-xs text-muted-foreground">{{ t('certificates.issue.keyUsages') }}</span>
                <Badge v-for="usage in keyUsages" :key="usage.usage" variant="secondary" class="font-mono text-xs">
                  {{ t(`certificates.ku.${usage.usage}`) }}
                  <span v-if="usage.rsaOnly" class="font-sans font-normal text-muted-foreground">{{ t('certificates.issue.rsaOnly') }}</span>
                </Badge>
              </div>
              <div v-if="template.extended_key_usages.length" class="flex flex-wrap items-center gap-1.5">
                <span class="mr-1 text-xs text-muted-foreground">{{ t('certificates.issue.extendedKeyUsages') }}</span>
                <Badge v-for="eku in template.extended_key_usages" :key="eku" variant="secondary" class="font-mono text-xs">{{ t(`certificates.eku.${eku}`) }}</Badge>
              </div>
              <div class="flex flex-wrap items-center gap-1.5">
                <span class="mr-1 text-xs text-muted-foreground">{{ t('tags.title') }}</span>
                <TagChip v-for="tag in pickedTags" :key="tag.id" :name="tag.name" :color="tag.color" />
                <TagPicker v-model="tagIds" :tags="allTags">
                  <Button type="button" variant="ghost" size="sm" class="h-6 px-2 text-xs text-muted-foreground"><TagIcon class="size-3" />{{ t('tags.editTags') }}</Button>
                </TagPicker>
              </div>
            </div>
          </template>
        </FieldGroup>
      </FormCard>

      <template v-if="template">
        <FormCard :step="2" :title="t('certificates.issue.key')">
          <CertKeySource v-model="key" id-prefix="issue" :algorithms="template.key_algorithms" :allow-keygen="template.allow_server_keygen" />
        </FormCard>

        <FormCard :step="3" :title="t('certificates.issue.names')">
          <FieldGroup>
            <Field v-if="cnAllowed">
              <div class="flex items-center gap-1.5">
                <FieldLabel for="issue-cn">{{ template.require_common_name ? t('certificates.issue.commonNameRequired') : t('certificates.issue.commonName') }}</FieldLabel>
                <InfoTip v-if="key.mode === 'csr'" :text="t('certificates.issue.commonNameCsrHint')" />
              </div>
              <Input id="issue-cn" v-model="commonName" maxlength="64" :required="template.require_common_name" autocomplete="off" spellcheck="false" />
            </Field>
            <CertSanEditor v-model="sans" id-prefix="issue" :types="template.allowed_san_types" :invalid="invalidSans" :info="key.mode === 'csr' ? t('certificates.issue.sansCsrHint') : undefined" />
          </FieldGroup>
        </FormCard>

        <FormCard :step="4" :title="t('certificates.issue.lifetime')">
          <Field>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="issue-ttl">{{ t('certificates.issue.ttl') }}</FieldLabel>
              <InfoTip :text="t('certificates.issue.ttlHint', { max: maxDays })" />
            </div>
            <Input id="issue-ttl" v-model.number="ttlDays" type="number" min="1" :max="maxDays" required class="sm:max-w-48" />
          </Field>
        </FormCard>
      </template>

      <Alert v-if="formError" class="border-danger/40 bg-danger-soft text-danger">
        <AlertDescription class="text-foreground">{{ formError }}</AlertDescription>
      </Alert>

      <div class="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="outline" as-child><NuxtLink to="/certificates">{{ t('common.cancel') }}</NuxtLink></Button>
        <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ t('certificates.issue.submit') }}</Button>
      </div>
    </form>
  </div>
</template>
