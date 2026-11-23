<script setup lang="ts">
import { ChevronRightIcon, InfoIcon, OctagonXIcon, PencilIcon, RefreshCwIcon, TriangleAlertIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateDetail, Tag } from '~/types/api'

/**
 * One certificate: its decoded fields, usages and names, validity, downloads, an `openssl
 * verify` command for the files offered here, renew and revoke. Imported certificates show only
 * what they hold: certifly did not issue them and cannot revoke or renew them.
 */
definePageMeta({ header: false, requires: ['instance', 'read_certificates'] })

const { t, d } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const id = computed(() => String(route.params.id))
const { data: cert, error } = await useAsyncData(
  () => `certificate-${id.value}`,
  async () => {
    const res = await rpc('certificates.get', { id: id.value })
    auth.remember(res.data)
    return res.data
  },
)
if (error.value || !cert.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

const title = computed(() => cert.value?.common_name ?? cert.value?.sans[0]?.value ?? t('certificates.untitled'))
useHead({ title: () => title.value })

// Tags: the managed list for the picker, and saving a new set straight away.
const { data: allTags } = await useAsyncData('certificate-tag-list', async () => (auth.can('instance', 'read_tags') ? (await rpc('tags.list')).data : []), { default: () => [] as Tag[] })
const tagIds = computed(() => cert.value?.tags.map((tag) => tag.id) ?? [])
const saveTags = useAction(async (ids: string[]) => {
  if (!cert.value) return
  cert.value = { ...cert.value, ...(await rpc('certificates.update', { id: cert.value.id, tag_ids: ids })).data }
  toast.success(t('tags.saved'))
})

const renewOpen = ref(false)
// The dashboard links here with ?renew=1 to open the renew dialog directly.
onMounted(() => {
  if (route.query.renew === '1' && can('renew')) renewOpen.value = true
})
const revokeOpen = ref(false)
const imported = computed(() => cert.value?.source === 'import')
const can = (ability: string) => auth.can(cert.value?.id, ability)
const fileName = computed(() => certificateFileName(cert.value?.common_name ?? cert.value?.sans[0]?.value))
const date = (value: string) => d(new Date(value), { dateStyle: 'medium', timeStyle: 'short' })
const colonHex = (hex: string | null) => hex?.toUpperCase().match(/.{1,2}/g)?.join(':') ?? '—'
const keyLabel = computed(() => {
  const key = cert.value?.details.public_key
  return key ? (key.type === 'ec' ? `ECDSA ${key.key_algorithm.replace('ecdsa-p', 'P-')}` : `RSA ${key.bits}`) : (cert.value?.key_algorithm ?? '')
})
const verifyCommand = computed(() => [`openssl verify -CAfile ${fileName.value}-chain.pem ${fileName.value}.pem`, `openssl x509 -in ${fileName.value}.pem -noout -text`].join('\n'))

function onRevoked(next: CertificateDetail) {
  auth.remember(next)
  cert.value = next
}

async function onRenewed(next: string) {
  await router.push(`/certificates/${next}`)
}
</script>

<template>
  <div v-if="cert">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('certificates.detail.back')">
        <NuxtLink to="/certificates" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('certificates.detail.back') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ title }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-2">
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="text-2xl font-semibold tracking-tight break-all">{{ title }}</h2>
            <CertStatusBadge :status="cert.status" />
            <Badge variant="outline" class="text-muted-foreground">{{ t(`certificates.sources.${cert.source}`) }}</Badge>
          </div>
          <p v-if="cert.subject_dn" class="font-mono text-xs break-all text-muted-foreground">{{ cert.subject_dn }}</p>
          <div class="flex flex-wrap gap-2">
            <MetaChip v-if="cert.template" :label="t('certificates.detail.template')"><NuxtLink :to="`/templates/${cert.template.id}`" class="text-primary underline-offset-4 hover:underline">{{ cert.template.name }}</NuxtLink></MetaChip>
            <MetaChip v-if="cert.ca" :label="t('certificates.detail.issuingCa')"><NuxtLink :to="`/certificate-authorities/${cert.ca.id}`" class="text-primary underline-offset-4 hover:underline">{{ cert.ca.name }}</NuxtLink></MetaChip>
            <MetaChip v-else :label="t('certificates.detail.issuedBy')"><span class="font-mono">{{ cert.issuer_dn }}</span></MetaChip>
          </div>
          <div class="flex flex-wrap items-center gap-1.5">
            <TagChip v-for="tag in cert.tags" :key="tag.id" :name="tag.name" :color="tag.color" />
            <span v-if="!cert.tags.length && !can('update_tags')" class="text-xs text-muted-foreground">{{ t('tags.none') }}</span>
            <TagPicker v-if="can('update_tags')" :model-value="tagIds" :tags="allTags" :apply="t('common.save')" :busy="saveTags.busy" @apply="saveTags">
              <Button variant="ghost" size="sm" class="h-6 px-2 text-xs text-muted-foreground"><PencilIcon class="size-3" />{{ t('tags.editTags') }}</Button>
            </TagPicker>
          </div>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button v-if="can('renew')" variant="outline" @click="renewOpen = true"><RefreshCwIcon />{{ t('certificates.detail.renew') }}</Button>
          <Button v-if="can('revoke')" variant="outline" class="text-destructive" @click="revokeOpen = true"><OctagonXIcon />{{ t('certificates.revoke.button') }}</Button>
        </div>
      </div>

      <Alert v-if="cert.status === 'revoked'" class="border-danger/40 bg-danger-soft text-danger">
        <OctagonXIcon />
        <AlertDescription class="text-foreground">
          {{ t('certificates.revoke.notice', { date: cert.revoked_at ? date(cert.revoked_at) : '—', reason: t(`revocation.reasons.${cert.revocation_reason ?? 'unspecified'}`) }) }}
        </AlertDescription>
      </Alert>
      <Alert v-else-if="imported">
        <InfoIcon />
        <AlertDescription>{{ t('certificates.detail.importedNotice') }}</AlertDescription>
      </Alert>

      <Alert v-if="cert.status === 'superseded' && cert.superseded_by_id">
        <InfoIcon />
        <AlertDescription>
          {{ t('certificates.detail.supersededNotice') }}
          <NuxtLink :to="`/certificates/${cert.superseded_by_id}`" class="font-medium text-primary underline-offset-4 hover:underline">{{ t('certificates.detail.openNewer') }}</NuxtLink>
        </AlertDescription>
      </Alert>
      <Alert v-else-if="cert.status === 'expired'" class="border-danger/40 bg-danger-soft text-danger">
        <TriangleAlertIcon />
        <AlertDescription class="text-foreground">{{ t('certificates.detail.expiredNotice') }}</AlertDescription>
      </Alert>
      <Alert v-else-if="cert.renew_due" class="border-warning/40 bg-warning-soft text-warning">
        <TriangleAlertIcon />
        <AlertDescription class="text-foreground">{{ t('certificates.detail.renewDueNotice') }}</AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('certificates.downloads.title') }}</CardTitle>
            <InfoTip :text="t(imported ? 'certificates.downloads.hintImported' : 'certificates.downloads.hintNoKey')" />
          </div>
        </CardHeader>
        <CardContent>
          <CertDownloads :certificate="cert" :file-name="fileName" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{{ t('certificates.detail.fields') }}</CardTitle>
        </CardHeader>
        <CardContent>
          <dl class="grid gap-x-6 gap-y-4 text-sm sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
            <dt class="text-muted-foreground">{{ t('certificates.detail.sans') }}</dt>
            <dd class="flex flex-wrap gap-1.5">
              <Badge v-for="san in cert.sans" :key="`${san.type}:${san.value}`" variant="secondary" class="font-mono text-xs break-all whitespace-normal">
                {{ t(`certificates.sanTypes.${san.type}`) }}: {{ san.value }}
              </Badge>
              <span v-if="!cert.sans.length" class="text-muted-foreground">—</span>
            </dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.validFrom') }}</dt>
            <dd><time :datetime="cert.not_before">{{ date(cert.not_before) }}</time></dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.validTo') }}</dt>
            <dd class="flex flex-col gap-0.5">
              <time :datetime="cert.not_after">{{ date(cert.not_after) }}</time>
              <CaExpiry :not-after="cert.not_after" relative />
            </dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.keyUsage') }}</dt>
            <dd class="flex flex-wrap gap-1.5">
              <Badge v-for="usage in cert.details.key_usages" :key="usage" variant="secondary" class="text-xs">{{ t(`certificates.ku.${usage}`) }}</Badge>
              <span v-if="!cert.details.key_usages.length" class="text-muted-foreground">—</span>
            </dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.extendedKeyUsage') }}</dt>
            <dd class="flex flex-wrap gap-1.5">
              <Badge v-for="eku in cert.extended_key_usages" :key="eku" variant="secondary" class="text-xs">{{ t(`certificates.eku.${eku}`) }}</Badge>
              <span v-if="!cert.extended_key_usages.length" class="text-muted-foreground">—</span>
            </dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.key') }}</dt>
            <dd>
              <span class="flex flex-wrap items-center gap-2">
                {{ keyLabel }}
                <Badge v-if="cert.key_generated" variant="outline" class="text-muted-foreground">{{ t('certificates.detail.keyGenerated') }}</Badge>
              </span>
            </dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.issuer') }}</dt>
            <dd class="font-mono text-xs break-all">{{ cert.issuer_dn }}</dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.serial') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.serial) }}</dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.fingerprint') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.fingerprint_sha256) }}</dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.ski') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.details.subject_key_identifier) }}</dd>
            <dt class="text-muted-foreground">{{ t('certificates.detail.aki') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.details.authority_key_identifier) }}</dd>
            <template v-if="cert.details.crl_urls.length">
              <dt class="text-muted-foreground">{{ t('certificates.detail.crlUrls') }}</dt>
              <dd class="font-mono text-xs break-all">{{ cert.details.crl_urls.join(', ') }}</dd>
            </template>
            <template v-if="cert.details.ca_issuer_urls.length">
              <dt class="text-muted-foreground">{{ t('certificates.detail.caIssuers') }}</dt>
              <dd class="font-mono text-xs break-all">{{ cert.details.ca_issuer_urls.join(', ') }}</dd>
            </template>
            <dt class="text-muted-foreground">{{ t('certificates.detail.issuedAt') }}</dt>
            <dd><time :datetime="cert.created_at">{{ date(cert.created_at) }}</time></dd>
            <template v-if="cert.supersedes_id">
              <dt class="text-muted-foreground">{{ t('certificates.detail.renewalOf') }}</dt>
              <dd><NuxtLink :to="`/certificates/${cert.supersedes_id}`" class="text-primary underline-offset-4 hover:underline">{{ t('certificates.detail.previous') }}</NuxtLink></dd>
            </template>
          </dl>
        </CardContent>
      </Card>

      <Card v-if="!imported">
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('certificates.detail.verify') }}</CardTitle>
            <InfoTip :text="t('certificates.detail.verifyHint')" />
          </div>
        </CardHeader>
        <CardContent>
          <CertCommand :command="verifyCommand" />
        </CardContent>
      </Card>
    </div>

    <CertRenewDialog v-model:open="renewOpen" :certificate="cert" @renewed="onRenewed" />
    <CertRevokeDialog v-model:open="revokeOpen" :certificate="cert" :name="title" @revoked="onRevoked" />
  </div>
</template>
