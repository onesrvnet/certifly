<script setup lang="ts">
import { toast } from 'vue-sonner'

/**
 * Create an SSH CA: name it, then either let certifly generate its key or import an existing
 * unencrypted private key. The key never leaves certifly. Refusals show next to their field.
 */
definePageMeta({ titleKey: 'sshCas.new.title', requires: ['instance', 'create_ssh_ca'] })

const { t } = useI18n()
const rpc = useRpc()
const router = useRouter()
const errorMessage = useErrorMessage()

useHead({ title: () => t('sshCas.new.title') })
useHead({ htmlAttrs: { style: 'scroll-padding: 5rem 0 5.5rem' } })

type Algorithm = 'ed25519' | 'ecdsa-p256' | 'rsa-4096'
const ALGORITHMS: Algorithm[] = ['ed25519', 'ecdsa-p256', 'rsa-4096']

const name = ref('')
const slug = ref('')
const description = ref('')
const mode = ref<'generate' | 'import'>('generate')
const algorithm = ref<Algorithm>('ed25519')
const privateKey = ref('')
const slugEdited = ref(false)
const errors = ref<{ slug?: string; privateKey?: string }>({})
const formError = ref('')

watch(name, (value) => {
  if (!slugEdited.value) slug.value = slugify(value)
})

const ready = computed(() => !!name.value.trim() && /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(slug.value) && (mode.value === 'generate' || privateKey.value.trim().length > 0))

const submit = useAction(async () => {
  errors.value = {}
  formError.value = ''
  const base = { name: name.value.trim(), slug: slug.value, description: description.value.trim() || undefined }
  try {
    const res = mode.value === 'generate'
      ? await rpc('ssh_cas.create', { ...base, key_algorithm: algorithm.value })
      : await rpc('ssh_cas.import', { ...base, private_key: privateKey.value })
    // The pasted key is not kept around.
    privateKey.value = ''
    toast.success(t('sshCas.new.created', { name: res.data.name }))
    await router.push(`/ssh/cas/${res.data.id}`)
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    if (error.code === 'slug_taken' || error.code === 'invalid_slug') errors.value = { slug: errorMessage(error) }
    else if (error.code === 'ssh_key_encrypted' || error.code === 'invalid_private_key' || error.code === 'unsupported_key') errors.value = { privateKey: errorMessage(error) }
    else formError.value = errorMessage(error)
  }
})
</script>

<template>
  <div class="mx-auto flex w-full max-w-3xl flex-col gap-6 p-4 md:p-10">
    <form class="flex min-w-0 flex-col gap-6" @submit.prevent="submit()">
      <Alert v-if="formError" class="border-danger/40 bg-danger-soft text-danger">
        <AlertDescription class="text-foreground">{{ formError }}</AlertDescription>
      </Alert>

      <FormCard :title="t('sshCas.new.general')">
        <FieldGroup>
          <Field>
            <FieldLabel for="ca-name">{{ t('sshCas.new.name') }}</FieldLabel>
            <Input id="ca-name" v-model="name" maxlength="100" required :placeholder="t('sshCas.new.namePlaceholder')" />
          </Field>
          <Field :data-invalid="!!errors.slug || undefined">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="ca-slug">{{ t('sshCas.new.slug') }}</FieldLabel>
              <InfoTip :text="t('sshCas.new.slugTip')" />
            </div>
            <Input id="ca-slug" v-model="slug" maxlength="64" required pattern="[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?" class="font-mono" @input="slugEdited = true" />
            <FieldError v-if="errors.slug">{{ errors.slug }}</FieldError>
          </Field>
          <Field>
            <FieldLabel for="ca-description">{{ t('sshCas.new.description') }}</FieldLabel>
            <Textarea id="ca-description" v-model="description" rows="2" maxlength="1000" />
          </Field>
        </FieldGroup>
      </FormCard>

      <FormCard :title="t('sshCas.new.key')" :info="t('sshCas.new.keyTip')">
        <FieldGroup>
          <Tabs v-model="mode">
            <TabsList>
              <TabsTrigger value="generate" class="px-3">{{ t('sshCas.new.generate') }}</TabsTrigger>
              <TabsTrigger value="import" class="px-3">{{ t('sshCas.new.import') }}</TabsTrigger>
            </TabsList>
          </Tabs>

          <Field v-if="mode === 'generate'">
            <FieldLabel for="ca-algorithm">{{ t('sshCas.new.keyType') }}</FieldLabel>
            <Select v-model="algorithm">
              <SelectTrigger id="ca-algorithm" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="value in ALGORITHMS" :key="value" :value="value">{{ sshKeyLabel(value) }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>

          <Field v-else :data-invalid="!!errors.privateKey || undefined">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="ca-private-key">{{ t('sshCas.new.privateKey') }}</FieldLabel>
              <InfoTip :text="t('sshCas.new.privateKeyTip')" />
            </div>
            <Textarea id="ca-private-key" v-model="privateKey" rows="8" spellcheck="false" autocomplete="off" class="font-mono text-xs break-all" :placeholder="t('sshCas.new.privateKeyPlaceholder')" />
            <FieldError v-if="errors.privateKey">{{ errors.privateKey }}</FieldError>
          </Field>
        </FieldGroup>
      </FormCard>

      <div class="sticky bottom-0 z-10 flex flex-wrap justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <Button type="button" variant="outline" as-child><NuxtLink to="/ssh/cas">{{ t('common.cancel') }}</NuxtLink></Button>
        <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ mode === 'generate' ? t('sshCas.new.submit') : t('sshCas.new.submitImport') }}</Button>
      </div>
    </form>
  </div>
</template>
