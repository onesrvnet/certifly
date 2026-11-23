<script setup lang="ts">
import { UploadIcon } from '@lucide/vue'

import type { KeyAlgorithm } from '~/types/api'

/**
 * Where the key comes from: a CSR (pasted or from a file), a key pair certifly generates and
 * hands out once (PEM, or PKCS#12 with a password), or, when renewing, the stored CSR.
 */
const state = defineModel<KeySourceState>({ required: true })
const props = defineProps<{ algorithms: KeyAlgorithm[]; allowKeygen: boolean; allowReuse?: boolean; idPrefix: string }>()
const { t } = useI18n()

// Generating the key comes first: it is the default for templates that allow it.
const modes = computed(() => [...(props.allowReuse ? (['reuse'] as const) : []), ...(props.allowKeygen ? (['keygen'] as const) : []), 'csr' as const])
const fileInput = ref<HTMLInputElement | null>(null)
const mismatch = computed(() => state.value.format === 'pkcs12' && !!state.value.confirm && state.value.password !== state.value.confirm)
const tooShort = computed(() => state.value.format === 'pkcs12' && !!state.value.password && state.value.password.length < MIN_PKCS12_PASSWORD)

async function onFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (file) state.value.csr = await readCsrFile(file)
  if (fileInput.value) fileInput.value.value = ''
}

watch(
  () => props.algorithms,
  (algorithms) => {
    // P-256 is the recommended leaf key; fall back to the template's first choice when it is not allowed.
    if (algorithms.length && !algorithms.includes(state.value.algorithm)) state.value.algorithm = algorithms.includes('ecdsa-p256') ? 'ecdsa-p256' : algorithms[0]!
  },
  { immediate: true },
)
watch(modes, (list) => {
  if (!list.includes(state.value.mode as never)) state.value.mode = list[0]!
})
</script>

<template>
  <div class="flex flex-col gap-4">
    <Tabs :model-value="state.mode" @update:model-value="state.mode = $event as KeySourceState['mode']">
      <TabsList class="w-full sm:w-auto">
        <TabsTrigger v-for="mode in modes" :key="mode" :value="mode">{{ t(`certificates.key.modes.${mode}`) }}</TabsTrigger>
      </TabsList>
    </Tabs>

    <p v-if="state.mode === 'reuse'" class="text-sm text-muted-foreground">{{ t('certificates.key.reuseHint') }}</p>

    <Field v-else-if="state.mode === 'csr'">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-1.5">
          <FieldLabel :for="`${idPrefix}-csr`">{{ t('certificates.key.csr') }}</FieldLabel>
          <InfoTip :text="t('certificates.key.csrHint')" />
        </div>
        <Button type="button" variant="outline" size="sm" @click="fileInput?.click()"><UploadIcon />{{ t('certificates.key.csrFile') }}</Button>
        <input ref="fileInput" type="file" accept=".csr,.pem,.req,.der,.txt" class="hidden" @change="onFile" />
      </div>
      <Textarea :id="`${idPrefix}-csr`" v-model="state.csr" rows="8" spellcheck="false" class="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE REQUEST-----" />
    </Field>

    <template v-else>
      <div class="grid gap-4 sm:grid-cols-2">
        <Field>
          <div class="flex items-center gap-1.5">
            <FieldLabel :for="`${idPrefix}-algorithm`">{{ t('certificates.key.algorithm') }}</FieldLabel>
            <InfoTip :text="t('certificates.key.keygenHint')" />
          </div>
          <Select v-model="state.algorithm">
            <SelectTrigger :id="`${idPrefix}-algorithm`" class="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="algorithm in algorithms" :key="algorithm" :value="algorithm">{{ algorithm === 'ecdsa-p256' ? `${t(`cas.algorithms.${algorithm}`)} ${t('cas.recommended')}` : t(`cas.algorithms.${algorithm}`) }}</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel :for="`${idPrefix}-format`">{{ t('certificates.key.format') }}</FieldLabel>
          <Select v-model="state.format">
            <SelectTrigger :id="`${idPrefix}-format`" class="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="pem">{{ t('certificates.key.formats.pem') }}</SelectItem>
              <SelectItem value="pkcs12">{{ t('certificates.key.formats.pkcs12') }}</SelectItem>
            </SelectContent>
          </Select>
        </Field>
      </div>
      <div v-if="state.format === 'pkcs12'" class="grid gap-4 sm:grid-cols-2">
        <Field :data-invalid="tooShort || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel :for="`${idPrefix}-password`">{{ t('certificates.key.password') }}</FieldLabel>
            <InfoTip :text="t('certificates.key.passwordHint', { min: MIN_PKCS12_PASSWORD })" />
          </div>
          <Input :id="`${idPrefix}-password`" v-model="state.password" type="password" autocomplete="new-password" :minlength="MIN_PKCS12_PASSWORD" maxlength="1024" />
          <FieldError v-if="tooShort">{{ t('certificates.key.passwordHint', { min: MIN_PKCS12_PASSWORD }) }}</FieldError>
        </Field>
        <Field :data-invalid="mismatch || undefined">
          <FieldLabel :for="`${idPrefix}-confirm`">{{ t('certificates.key.confirm') }}</FieldLabel>
          <Input :id="`${idPrefix}-confirm`" v-model="state.confirm" type="password" autocomplete="new-password" maxlength="1024" />
          <FieldError v-if="mismatch">{{ t('certificates.key.mismatch') }}</FieldError>
        </Field>
      </div>
    </template>
  </div>
</template>
