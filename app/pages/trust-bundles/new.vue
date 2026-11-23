<script setup lang="ts">
import { ChevronRightIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateAuthority } from '~/types/api'
import { emptyTraefikForm, traefikPayload, type TrustBundleFormState } from '~/utils/trustBundleForm'

/** Create a trust bundle: name it, give it a slug for its public URL, and pick the CAs. */
definePageMeta({ header: false, requires: ['instance', 'create_trust_bundle'] })

const { t } = useI18n()
const rpc = useRpc()
const router = useRouter()
const errorMessage = useErrorMessage()

useHead({ title: () => t('trustBundles.new.title') })

const { data: cas } = await useAsyncData('trust-bundle-cas', () => loadAllCas(rpc), { default: () => [] as CertificateAuthority[] })

const form = ref<TrustBundleFormState>({ name: '', slug: '', description: '', ca_ids: [], include_chain: false, ...emptyTraefikForm() })
const formError = ref('')
const formErrorCode = ref('')
const token = ref<string | null>(null)
const createdId = ref('')
watch(token, async (value) => {
  if (!value && createdId.value) await router.push(`/trust-bundles/${createdId.value}`)
})
const ready = computed(() => !!form.value.name.trim() && /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(form.value.slug) && form.value.ca_ids.length > 0)

const submit = useAction(async () => {
  formError.value = ''
  formErrorCode.value = ''
  try {
    const res = await rpc('trust_bundles.create', {
      name: form.value.name.trim(),
      slug: form.value.slug,
      description: form.value.description.trim() || undefined,
      ca_ids: form.value.ca_ids,
      include_chain: form.value.include_chain,
      ...traefikPayload(form.value),
    })
    toast.success(t('trustBundles.new.created', { name: res.data.name }))
    createdId.value = res.data.id
    // A new token is shown once, before leaving the page.
    if (res.data.traefik_token) token.value = res.data.traefik_token
    else await router.push(`/trust-bundles/${res.data.id}`)
  } catch (error) {
    // Refusals of the input show on the form; re-authentication and the rest go the usual way.
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409 && error.status !== 404)) throw error
    formError.value = errorMessage(error)
    formErrorCode.value = error.code
  }
})
</script>

<template>
  <div>
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('trustBundles.back')">
        <NuxtLink to="/trust-bundles" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('nav.trustBundles') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ t('trustBundles.new.title') }}</h1>
      </nav>
    </PageHeader>
    <form class="mx-auto flex w-full max-w-2xl flex-col gap-6 p-4 md:p-10" @submit.prevent="submit()">
      <TrustBundleForm v-model="form" mode="create" :cas="cas" :error="formError" :error-code="formErrorCode" />
      <div class="flex justify-end gap-2">
        <Button type="button" variant="outline" as-child><NuxtLink to="/trust-bundles">{{ t('common.cancel') }}</NuxtLink></Button>
        <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ t('trustBundles.submit') }}</Button>
      </div>
    </form>
    <TrustBundleTokenDialog v-model="token" />
  </div>
</template>
