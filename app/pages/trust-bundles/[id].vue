<script setup lang="ts">
import { ChevronRightIcon, CopyIcon, DownloadIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateAuthority, TrustBundleDetail } from '~/types/api'
import { traefikFormOf, traefikPayload, type TrustBundleFormState } from '~/utils/trustBundleForm'

/**
 * One trust bundle: its public URL, its Traefik endpoint when that is on, the certificates the PEM holds right now, and, for admins,
 * editing its CAs and deleting it.
 */
definePageMeta({ header: false, requires: ['instance', 'read_trust_bundles'] })

const { t, d } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const errorMessage = useErrorMessage()

const id = computed(() => String(route.params.id))
const { data: bundle, error } = await useAsyncData(`trust-bundle-${id.value}`, async () => {
  const res = await rpc('trust_bundles.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !bundle.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

useHead({ title: () => bundle.value?.name ?? t('nav.trustBundles') })

const can = (ability: string) => auth.can(bundle.value?.id, ability)
const { data: cas } = await useAsyncData('trust-bundle-cas', () => (can('update') ? loadAllCas(rpc) : Promise.resolve([])), { default: () => [] as CertificateAuthority[] })

const toForm = (value: TrustBundleDetail): TrustBundleFormState => ({
  name: value.name,
  slug: value.slug,
  description: value.description,
  ca_ids: value.cas.map((ca) => ca.id),
  include_chain: value.include_chain,
  ...traefikFormOf(value),
})
const form = ref<TrustBundleFormState>(toForm(bundle.value))
const formError = ref('')
const formErrorCode = ref('')
const editing = ref(false)

/** A token that was just made is shown once in a dialog and kept nowhere else. */
const token = ref<string | null>(null)

function replace(next: TrustBundleDetail) {
  auth.remember(next)
  if (next.traefik_token) token.value = next.traefik_token
  bundle.value = { ...next, traefik_token: null }
  form.value = toForm(next)
}

const save = useAction(async () => {
  formError.value = ''
  formErrorCode.value = ''
  try {
    const res = await rpc('trust_bundles.update', {
      id: id.value,
      name: form.value.name.trim(),
      description: form.value.description.trim(),
      ca_ids: form.value.ca_ids,
      include_chain: form.value.include_chain,
      ...traefikPayload(form.value),
    })
    replace(res.data)
    editing.value = false
    toast.success(t('common.saved'))
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409 && error.status !== 404)) throw error
    formError.value = errorMessage(error)
    formErrorCode.value = error.code
  }
})

function cancel() {
  if (bundle.value) form.value = toForm(bundle.value)
  formError.value = ''
  formErrorCode.value = ''
  editing.value = false
}

const deleteOpen = ref(false)
const remove = useAction(async () => {
  await rpc('trust_bundles.delete', { id: id.value })
  toast.success(t('trustBundles.deleted', { name: bundle.value?.name ?? '' }))
  deleteOpen.value = false
  await router.push('/trust-bundles')
})

// The static configuration that points a Traefik at the endpoint.
const traefikSnippet = computed(() => {
  if (!bundle.value) return ''
  const headers = bundle.value.traefik_require_token ? ['    headers:', `      Authorization: Bearer <${t('trustBundles.traefik.tokenPlaceholder')}>`] : []
  return ['providers:', '  http:', `    endpoint: ${bundle.value.traefik_url}`, '    pollInterval: 60s', ...headers].join('\n')
})
async function copySnippet() {
  await navigator.clipboard.writeText(traefikSnippet.value)
  toast.success(t('common.copied'))
}

const regenerateOpen = ref(false)
const regenerate = useAction(async () => {
  replace((await rpc('trust_bundles.regenerate_traefik_token', { id: id.value })).data)
  regenerateOpen.value = false
})

const caName = (caId: string) => bundle.value?.cas.find((ca) => ca.id === caId)?.name ?? ''
</script>

<template>
  <div v-if="bundle">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('trustBundles.back')">
        <NuxtLink to="/trust-bundles" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('nav.trustBundles') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ bundle.name }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-2">
          <h2 class="text-2xl font-semibold tracking-tight break-words">{{ bundle.name }}</h2>
          <p class="font-mono text-xs text-muted-foreground">{{ bundle.slug }}</p>
          <p v-if="bundle.description" class="max-w-2xl text-sm text-muted-foreground">{{ bundle.description }}</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button variant="outline" as-child>
            <a :href="bundle.path" :download="`${bundle.slug}.pem`"><DownloadIcon />{{ t('trustBundles.download') }}</a>
          </Button>
          <Button v-if="can('update') && !editing" variant="outline" @click="editing = true">{{ t('trustBundles.edit') }}</Button>
          <Button v-if="can('delete')" variant="outline" class="text-destructive" @click="deleteOpen = true"><Trash2Icon />{{ t('trustBundles.delete') }}</Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('trustBundles.publicUrl') }}</CardTitle>
            <InfoTip :text="t('trustBundles.publicUrlHint')" />
          </div>
        </CardHeader>
        <CardContent>
          <CaCopyField :label="t('trustBundles.pemUrl')" :value="bundle.url" />
        </CardContent>
      </Card>

      <Card v-if="bundle.traefik_enabled">
        <CardHeader>
          <div class="flex min-w-0 items-center gap-2">
            <CardTitle>{{ t('trustBundles.traefik.title') }}</CardTitle>
            <InfoTip :text="t('trustBundles.traefik.info')" />
          </div>
          <CardAction v-if="bundle.traefik_require_token && can('update')">
            <Button variant="outline" size="sm" @click="regenerateOpen = true">{{ t('trustBundles.traefik.regenerate') }}</Button>
          </CardAction>
        </CardHeader>
        <CardContent class="flex flex-col gap-4">
          <CaCopyField :label="t('trustBundles.traefik.endpoint')" :value="bundle.traefik_url" />
          <div class="flex flex-wrap gap-2">
            <MetaChip v-if="bundle.traefik_refs.tls_option" :label="t('trustBundles.traefik.tlsOption')">{{ bundle.traefik_refs.tls_option }}</MetaChip>
            <MetaChip v-if="bundle.traefik_refs.servers_transport" :label="t('trustBundles.traefik.serversTransport')">{{ bundle.traefik_refs.servers_transport }}</MetaChip>
          </div>
          <div class="flex min-w-0 flex-col gap-1">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs text-muted-foreground">{{ t('trustBundles.traefik.staticConfig') }}</span>
              <Button variant="outline" size="icon-sm" class="shrink-0" :aria-label="t('trustBundles.traefik.copySnippet')" :title="t('trustBundles.traefik.copySnippet')" @click="copySnippet">
                <CopyIcon />
              </Button>
            </div>
            <pre class="overflow-x-auto rounded-md border bg-muted/40 p-3 font-mono text-xs"><code>{{ traefikSnippet }}</code></pre>
          </div>
        </CardContent>
      </Card>

      <form v-if="editing" class="flex flex-col gap-6" :aria-label="t('trustBundles.edit')" @submit.prevent="save()">
        <TrustBundleForm v-model="form" mode="edit" :cas="cas" :error="formError" :error-code="formErrorCode" />
        <div class="flex justify-end gap-2">
          <Button type="button" variant="outline" @click="cancel">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="save.busy" :disabled="!form.name.trim() || !form.ca_ids.length">{{ t('common.save') }}</Button>
        </div>
      </form>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('trustBundles.contents') }}</CardTitle>
            <InfoTip :text="bundle.include_chain ? t('trustBundles.contentsHintChain') : t('trustBundles.contentsHint')" />
          </div>
        </CardHeader>
        <CardContent>
          <p v-if="!bundle.certificates.length" class="text-sm text-muted-foreground">{{ t('trustBundles.noCertificates') }}</p>
          <ul v-else class="divide-y rounded-md border">
            <li v-for="cert in bundle.certificates" :key="cert.fingerprint_sha256" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
              <span class="min-w-0 flex-1 font-medium break-words">{{ commonNameOf(cert.subject) }}</span>
              <Badge v-if="cert.from_chain" variant="outline" class="text-muted-foreground">{{ t('trustBundles.fromChain', { ca: caName(cert.ca_id) }) }}</Badge>
              <span class="w-full text-xs text-muted-foreground sm:w-auto">{{ t('trustBundles.expires', { date: d(new Date(cert.not_after), { dateStyle: 'medium' }) }) }}</span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>

    <Dialog v-model:open="regenerateOpen">
      <DialogContent class="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{{ t('trustBundles.traefik.regenerateTitle') }}</DialogTitle>
          <DialogDescription>{{ t('trustBundles.traefik.regenerateDescription') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="regenerateOpen = false">{{ t('common.cancel') }}</Button>
          <Button :loading="regenerate.busy" @click="regenerate()">{{ t('trustBundles.traefik.regenerate') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <TrustBundleTokenDialog v-model="token" />

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{{ t('trustBundles.deleteTitle', { name: bundle.name }) }}</DialogTitle>
          <DialogDescription>{{ t('trustBundles.deleteDescription') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('trustBundles.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
