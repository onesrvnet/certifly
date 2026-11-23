<script setup lang="ts">
import { ArchiveIcon, ChevronRightIcon, FilePlusIcon, InfoIcon, TriangleAlertIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateAuthority, Template, Tag } from '~/types/api'

/**
 * One template: its rules, editable by admins (read-only for everyone else), with a warning when
 * it is bound to a root, and archive. Operators start issuing from here.
 */
definePageMeta({ header: false, requires: ['instance', 'read_templates'] })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()
const auth = useAuthStore()
const errorMessage = useErrorMessage()

const id = computed(() => String(route.params.id))
const { data: template, error } = await useAsyncData(`template-${id.value}`, async () => {
  const res = await rpc('templates.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !template.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

const [{ data: allCas }, { data: tags }] = await Promise.all([
  useAsyncData('template-cas', async () => (await rpc('certificate_authorities.list', { limit: 200 })).data, { default: () => [] as CertificateAuthority[] }),
  useAsyncData('template-tags', async () => (await rpc('tags.list')).data, { default: () => [] as Tag[] }),
])

useHead({ title: () => template.value?.name ?? t('nav.templates') })
// Keep focused fields clear of the sticky page header and save bar.
useHead({ htmlAttrs: { style: 'scroll-padding: 5rem 0 5.5rem' } })

const can = (ability: string) => auth.can(template.value?.id, ability)
const editable = computed(() => can('update'))
// The bound CA stays in the list even when it can no longer take new templates, so the form shows it.
const cas = computed(() => allCas.value.filter((ca) => ca.status === 'active' || ca.id === template.value?.ca_id))

const form = ref<TemplateFormState>(formFromTemplate(template.value!))
const errors = ref<TemplateFormErrors>({ fields: {}, problems: [] })
const formError = ref('')
const archiveOpen = ref(false)

function replace(next: Template) {
  auth.remember(next)
  template.value = next
  form.value = formFromTemplate(next)
}

const save = useAction(async () => {
  errors.value = { fields: {}, problems: [] }
  formError.value = ''
  try {
    const res = await rpc('templates.update', {
      id: id.value,
      ...settingsFromForm(form.value),
      name: form.value.name.trim(),
      description: form.value.description.trim(),
      ca_id: form.value.ca_id,
      tag_ids: form.value.tag_ids,
    })
    replace(res.data)
    toast.success(t('templates.detail.saved'))
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    errors.value = templateFormErrors(error, errorMessage(error))
    formError.value = errorMessage(error)
  }
})

/** The protocol switches save on their own; unsaved edits in the form above stay. */
function protocolsChanged(next: Template) {
  auth.remember(next)
  template.value = next
}

function reset() {
  if (template.value) form.value = formFromTemplate(template.value)
  errors.value = { fields: {}, problems: [] }
  formError.value = ''
}
</script>

<template>
  <div v-if="template">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('templates.detail.back')">
        <NuxtLink to="/templates" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('templates.detail.back') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ template.name }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto w-full max-w-3xl p-4 md:p-10 lg:grid lg:max-w-[60.5rem] lg:grid-cols-[10rem_minmax(0,1fr)] lg:gap-10">
      <TemplateSectionNav class="hidden lg:block" />
      <div class="flex min-w-0 flex-col gap-6">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div class="flex min-w-0 flex-col gap-2">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="text-2xl font-semibold tracking-tight break-words">{{ template.name }}</h2>
              <Badge variant="outline" class="text-muted-foreground">{{ t(`templates.kinds.${template.usage_hint}`) }}</Badge>
              <Badge v-if="template.status === 'archived'" variant="outline" class="border-border bg-muted text-muted-foreground">{{ t('templates.status.archived') }}</Badge>
            </div>
            <div class="flex flex-wrap gap-2">
              <MetaChip :label="t('templates.detail.issuingCa')"><NuxtLink :to="`/certificate-authorities/${template.ca.id}`" class="text-primary underline-offset-4 hover:underline">{{ template.ca.name }}</NuxtLink></MetaChip>
              <MetaChip :label="t('templates.detail.slug')"><span class="font-mono">{{ template.slug }}</span></MetaChip>
            </div>
          </div>
          <div class="flex flex-wrap gap-2">
            <Button v-if="can('issue')" as-child>
              <NuxtLink :to="{ path: '/certificates/issue', query: { template: template.id } }"><FilePlusIcon />{{ t('templates.detail.issue') }}</NuxtLink>
            </Button>
            <Button v-if="can('archive')" variant="outline" class="text-destructive" @click="archiveOpen = true"><ArchiveIcon />{{ t('templates.detail.archive') }}</Button>
          </div>
        </div>

        <Alert v-if="template.bound_to_root" class="border-warning/40 bg-warning-soft text-warning">
          <TriangleAlertIcon />
          <AlertTitle>{{ t('templates.rootWarningTitle') }}</AlertTitle>
          <AlertDescription class="text-foreground">{{ t('templates.rootWarning') }}</AlertDescription>
        </Alert>
        <Alert v-if="template.max_ttl_exceeds_ca && template.ca_remaining_seconds !== null" class="border-info/40 bg-info-soft text-info">
          <InfoIcon />
          <AlertDescription class="text-foreground">{{ t('templates.ttlExceedsCa', { days: Math.floor(template.ca_remaining_seconds / DAY_SECONDS) }) }}</AlertDescription>
        </Alert>
        <Alert v-if="template.status === 'archived'">
          <InfoIcon />
          <AlertDescription>{{ t('templates.detail.archivedNotice') }}</AlertDescription>
        </Alert>
        <Alert v-else-if="!editable">
          <InfoIcon />
          <AlertDescription>{{ t('templates.detail.readOnly') }}</AlertDescription>
        </Alert>

        <form class="flex flex-col gap-6" @submit.prevent="save()">
          <Alert v-if="formError" class="border-danger/40 bg-danger-soft text-danger">
            <AlertDescription class="text-foreground">{{ formError }}</AlertDescription>
          </Alert>
          <TemplateForm v-model="form" :cas="cas" :tags="tags" mode="edit" :errors="errors" :disabled="!editable" />
          <div v-if="editable" class="sticky bottom-0 z-10 flex flex-wrap justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur supports-[backdrop-filter]:bg-background/80">
            <Button type="button" variant="outline" @click="reset">{{ t('templates.detail.reset') }}</Button>
            <Button type="submit" :loading="save.busy">{{ t('common.save') }}</Button>
          </div>
        </form>

        <TemplateProtocolsCard :template="template" @updated="protocolsChanged" />
      </div>
    </div>

    <TemplateArchiveDialog v-model:open="archiveOpen" :template="template" @archived="replace" />
  </div>
</template>
