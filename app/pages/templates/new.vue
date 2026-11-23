<script setup lang="ts">
import { ArrowLeftIcon, GlobeIcon, MonitorSmartphoneIcon, ServerIcon, ShieldCheckIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateAuthority, TemplatePreset, TemplatePresetId, Tag } from '~/types/api'

/**
 * Create a template in two steps: pick a preset, then pick the CA and adjust what the preset
 * filled in. Refusals from the server show next to the field they concern.
 */
definePageMeta({ titleKey: 'templates.new.title', requires: ['instance', 'create_template'] })

const { t } = useI18n()
const rpc = useRpc()
const router = useRouter()
const errorMessage = useErrorMessage()

useHead({ title: () => t('templates.new.title') })
// Keep focused fields clear of the sticky page header and save bar.
useHead({ htmlAttrs: { style: 'scroll-padding: 5rem 0 5.5rem' } })

const ICONS: Record<TemplatePresetId, unknown> = { webserver_tls: GlobeIcon, mtls_server: ServerIcon, mtls_client: MonitorSmartphoneIcon, server_client: ShieldCheckIcon }

const [{ data: presets }, { data: cas }, { data: tags }] = await Promise.all([
  useAsyncData('template-presets', async () => (await rpc('template_presets.list')).data, { default: () => [] as TemplatePreset[] }),
  useAsyncData('template-cas', async () => bindableCas((await rpc('certificate_authorities.list', { limit: 200 })).data), { default: () => [] as CertificateAuthority[] }),
  useAsyncData('template-tags', async () => (await rpc('tags.list')).data, { default: () => [] as Tag[] }),
])

const preset = ref<TemplatePreset | null>(null)
const form = ref<TemplateFormState | null>(null)
const errors = ref<TemplateFormErrors>({ fields: {}, problems: [] })

function choose(value: TemplatePreset) {
  preset.value = value
  const next = formFromPreset(value, t(`templates.presets.${value.id}.title`))
  // An issuing CA is the better default; roots come last.
  next.ca_id = [...cas.value].sort((a, b) => Number(a.signing === 'self_signed') - Number(b.signing === 'self_signed'))[0]?.id ?? ''
  form.value = next
  errors.value = { fields: {}, problems: [] }
}

const ready = computed(() => !!form.value && !!form.value.name.trim() && !!form.value.ca_id && /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(form.value.slug))
const formError = ref('')

const submit = useAction(async () => {
  if (!form.value || !preset.value) return
  errors.value = { fields: {}, problems: [] }
  formError.value = ''
  try {
    const res = await rpc('templates.create', {
      ...settingsFromForm(form.value),
      name: form.value.name.trim(),
      slug: form.value.slug,
      description: form.value.description.trim() || undefined,
      ca_id: form.value.ca_id,
      tag_ids: form.value.tag_ids,
      preset: preset.value.id,
    })
    toast.success(t('templates.new.created', { name: res.data.name }))
    await router.push(`/templates/${res.data.id}`)
  } catch (error) {
    // Refusals of the input are shown on the form; everything else (and re-authentication) goes the usual way.
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    errors.value = templateFormErrors(error, errorMessage(error))
    formError.value = errorMessage(error)
  }
})
</script>

<template>
  <div class="mx-auto flex w-full flex-col gap-8 p-4 md:p-10" :class="form ? 'max-w-3xl lg:max-w-[60.5rem]' : 'max-w-3xl'">
    <section v-if="!form" class="flex flex-col gap-4">
      <h2 class="text-lg font-semibold tracking-tight">{{ t('templates.new.choosePreset') }}</h2>
      <p v-if="!cas.length" class="text-sm text-muted-foreground">{{ t('templates.form.noCas') }}</p>
      <div class="grid gap-3 sm:grid-cols-2">
        <button
          v-for="option in presets"
          :key="option.id"
          type="button"
          class="flex flex-col items-start gap-2 rounded-lg border p-4 text-left transition-colors hover:bg-accent/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
          @click="choose(option)"
        >
          <component :is="ICONS[option.id]" class="size-5 text-primary" />
          <span class="font-medium">{{ t(`templates.presets.${option.id}.title`) }}</span>
          <span class="text-sm text-muted-foreground">{{ t(`templates.presets.${option.id}.description`) }}</span>
          <span class="mt-1 flex flex-wrap gap-1.5">
            <Badge v-for="eku in option.extended_key_usages" :key="eku" variant="secondary" class="font-mono text-xs">{{ t(`certificates.eku.${eku}`) }}</Badge>
            <Badge variant="outline" class="text-xs text-muted-foreground">{{ t('templates.new.presetTtl', { days: secondsToDays(option.default_ttl_seconds), max: secondsToDays(option.max_ttl_seconds) }) }}</Badge>
          </span>
        </button>
      </div>
    </section>

    <div v-else class="lg:grid lg:grid-cols-[10rem_minmax(0,1fr)] lg:gap-10">
      <TemplateSectionNav class="hidden lg:block" />
      <form class="flex min-w-0 flex-col gap-6" @submit.prevent="submit()">
        <div class="flex flex-wrap items-center gap-3">
          <Button type="button" variant="ghost" size="sm" @click="form = null"><ArrowLeftIcon />{{ t('common.back') }}</Button>
          <h2 class="text-lg font-semibold tracking-tight">{{ t(`templates.presets.${preset!.id}.title`) }}</h2>
        </div>

        <Alert v-if="formError" class="border-danger/40 bg-danger-soft text-danger">
          <AlertDescription class="text-foreground">{{ formError }}</AlertDescription>
        </Alert>

        <TemplateForm v-model="form" :cas="cas" :tags="tags" mode="create" :errors="errors" />

        <div class="sticky bottom-0 z-10 flex flex-wrap justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur supports-[backdrop-filter]:bg-background/80">
          <Button type="button" variant="outline" as-child><NuxtLink to="/templates">{{ t('common.cancel') }}</NuxtLink></Button>
          <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ t('templates.new.submit') }}</Button>
        </div>
      </form>
    </div>
  </div>
</template>
