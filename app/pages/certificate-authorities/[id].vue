<script setup lang="ts">
import { BanIcon, ChevronRightIcon, DownloadIcon, InfoIcon, OctagonXIcon, RefreshCwIcon, TriangleAlertIcon, UploadIcon } from '@lucide/vue'

import type { CertificateAuthorityDetail } from '~/types/api'

/**
 * One CA: its status, the decoded active certificate, chain and versions, the public URLs, the
 * CSR steps while an externally signed CA waits for its certificate, and renew and disable.
 */
definePageMeta({ header: false, requires: ['instance', 'read_certificate_authorities'] })

const { t, d, locale } = useI18n()
const rpc = useRpc()
const route = useRoute()
const auth = useAuthStore()

const id = computed(() => String(route.params.id))
const { data: ca, error } = await useAsyncData(`ca-${id.value}`, async () => {
  const res = await rpc('certificate_authorities.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !ca.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

useHead({ title: () => ca.value?.name ?? t('nav.certificateAuthorities') })

/** After an action, show what the server returned and keep the permissions it carries. */
function replace(next: CertificateAuthorityDetail) {
  auth.remember(next)
  ca.value = next
}

const importOpen = ref(false)
const renewOpen = ref(false)
const disableOpen = ref(false)
const revokeOpen = ref(false)

const can = (ability: string) => auth.can(ca.value?.id, ability)
const cert = computed(() => ca.value?.active_certificate ?? null)
const fullChainPem = computed(() => (cert.value ? cert.value.pem + (ca.value?.chain_pem ?? '') : ''))
const date = (value: string) => d(new Date(value), { dateStyle: 'medium', timeStyle: 'short' })
const keyLabel = computed(() => {
  const key = cert.value?.public_key
  return key ? (key.type === 'ec' ? `ECDSA ${key.key_algorithm.replace('ecdsa-p', 'P-')}` : `RSA ${key.bits}`) : (ca.value?.key_algorithm ?? '')
})
/** CRLs of keys the CA no longer signs with; they stay while what those keys signed is valid. */
const olderCrls = computed(() => ca.value?.crls.filter((crl) => !crl.active) ?? [])
const colonHex = (hex: string | null) => hex?.toUpperCase().match(/.{1,2}/g)?.join(':') ?? '—'
</script>

<template>
  <div v-if="ca">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('cas.detail.back')">
        <NuxtLink to="/certificate-authorities" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('cas.detail.back') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ ca.name }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-2">
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="text-2xl font-semibold tracking-tight break-words">{{ ca.name }}</h2>
            <CaStatusBadge :status="ca.status" :revoked="!!ca.revoked_at" />
            <Badge variant="outline" class="text-muted-foreground">{{ t(`cas.signing.${ca.signing}`) }}</Badge>
          </div>
          <p class="font-mono text-xs break-all text-muted-foreground">{{ ca.subject_dn }}</p>
          <p v-if="ca.description" class="max-w-2xl text-sm text-muted-foreground">{{ ca.description }}</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button v-if="can('import') && ca.active_certificate" variant="outline" @click="importOpen = true"><UploadIcon />{{ t('cas.detail.importRenewed') }}</Button>
          <Button v-if="can('renew')" variant="outline" @click="renewOpen = true"><RefreshCwIcon />{{ t('cas.detail.renew') }}</Button>
          <Button v-if="can('disable')" variant="outline" class="text-destructive" @click="disableOpen = true"><BanIcon />{{ t('cas.detail.disable') }}</Button>
          <Button v-if="can('revoke')" variant="outline" class="text-destructive" @click="revokeOpen = true">
            <OctagonXIcon />{{ ca.signing === 'external' ? t('cas.markCompromised.button') : t('cas.revoke.button') }}
          </Button>
        </div>
      </div>

      <Alert v-if="ca.revoked_at" class="border-danger/40 bg-danger-soft text-danger">
        <TriangleAlertIcon />
        <AlertTitle>{{ ca.signing === 'external' ? t('cas.markCompromised.noticeTitle') : t('cas.revoke.noticeTitle') }}</AlertTitle>
        <AlertDescription class="text-foreground">
          {{
            t(ca.signing === 'external' ? 'cas.markCompromised.notice' : 'cas.revoke.notice', {
              date: date(ca.revoked_at),
              reason: t(`revocation.reasons.${ca.revocation_reason ?? 'unspecified'}`),
            })
          }}
        </AlertDescription>
      </Alert>
      <Alert v-else-if="ca.status === 'disabled' || ca.status === 'expired'" :class="ca.status === 'expired' ? 'border-danger/40 bg-danger-soft text-danger' : ''">
        <InfoIcon />
        <AlertDescription :class="ca.status === 'expired' ? 'text-foreground' : ''">{{ ca.status === 'disabled' ? t('cas.detail.disabledNotice') : t('cas.detail.expiredNotice') }}</AlertDescription>
      </Alert>

      <CaCsrPanel v-if="ca.pending_csr" :ca="ca" :can-import="can('import')" @import="importOpen = true" />

      <Card>
        <CardHeader>
          <CardTitle>{{ t('cas.detail.certificate') }}</CardTitle>
          <CardAction v-if="cert" class="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" @click="downloadText(`${ca.slug}.pem`, cert.pem)"><DownloadIcon />{{ t('cas.detail.downloadCertificate') }}</Button>
            <Button variant="outline" size="sm" @click="downloadText(`${ca.slug}-chain.pem`, fullChainPem)"><DownloadIcon />{{ t('cas.detail.downloadChain') }}</Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          <p v-if="!cert" class="text-sm text-muted-foreground">{{ t('cas.detail.noCertificate') }}</p>
          <dl v-else class="grid gap-x-6 gap-y-4 text-sm sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
            <dt class="text-muted-foreground">{{ t('cas.detail.issuer') }}</dt>
            <dd class="font-mono text-xs break-all">{{ cert.issuer }}</dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.validFrom') }}</dt>
            <dd><time :datetime="cert.not_before">{{ date(cert.not_before) }}</time></dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.validTo') }}</dt>
            <dd class="flex flex-col gap-0.5">
              <time :datetime="cert.not_after">{{ date(cert.not_after) }}</time>
              <CaExpiry :not-after="cert.not_after" relative />
            </dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.keyAlgorithm') }}</dt>
            <dd>{{ keyLabel }}</dd>
            <dt class="text-muted-foreground">{{ t('cas.pathLength') }}</dt>
            <dd>{{ cert.path_length ?? t('cas.pathLengthUnlimited') }}</dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.keyUsage') }}</dt>
            <dd class="flex flex-wrap gap-1.5">
              <Badge v-for="usage in cert.key_usages" :key="usage" variant="secondary" class="font-mono text-xs">{{ usage }}</Badge>
            </dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.serial') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.serial) }}</dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.fingerprint') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.fingerprint_sha256) }}</dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.ski') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.subject_key_identifier) }}</dd>
            <dt class="text-muted-foreground">{{ t('cas.detail.aki') }}</dt>
            <dd class="font-mono text-xs break-all">{{ colonHex(cert.authority_key_identifier) }}</dd>
            <template v-if="cert.crl_urls.length">
              <dt class="text-muted-foreground">{{ t('cas.detail.crlUrls') }}</dt>
              <dd class="font-mono text-xs break-all">{{ cert.crl_urls.join(', ') }}</dd>
            </template>
            <template v-if="cert.ca_issuer_urls.length">
              <dt class="text-muted-foreground">{{ t('cas.detail.caIssuers') }}</dt>
              <dd class="font-mono text-xs break-all">{{ cert.ca_issuer_urls.join(', ') }}</dd>
            </template>
          </dl>
        </CardContent>
      </Card>

      <div class="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{{ t('cas.detail.constraints') }}</CardTitle>
          </CardHeader>
          <CardContent>
            <CaNameConstraintsView :constraints="ca.name_constraints" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div class="flex items-center gap-1.5">
              <CardTitle>{{ t('cas.detail.crl') }}</CardTitle>
              <InfoTip :text="t('cas.detail.crlSchedule', { validity: ca.crl_validity_hours, overlap: ca.crl_overlap_hours })" />
            </div>
          </CardHeader>
          <CardContent class="flex flex-col gap-1 text-sm">
            <template v-if="ca.crl">
              <span class="font-medium">{{ t('cas.detail.crlNumber', { number: ca.crl.crl_number }) }}</span>
              <span class="text-muted-foreground">{{ t('cas.detail.crlUpdated', { time: timeAgo(ca.crl.this_update, locale) }) }}</span>
              <span class="text-muted-foreground">{{ t('cas.detail.crlNext', { date: date(ca.crl.next_update) }) }}</span>
            </template>
            <p v-else class="text-muted-foreground">{{ t('cas.detail.crlNone') }}</p>
            <div v-if="olderCrls.length" class="mt-3 flex flex-col gap-2 border-t pt-3">
              <span class="text-xs text-muted-foreground">{{ t('cas.detail.olderKeyCrls') }}</span>
              <div v-for="crl in olderCrls" :key="crl.key_id" class="flex min-w-0 flex-col gap-0.5">
                <span class="truncate font-mono text-xs" :title="crl.key_id">{{ t('cas.detail.crlKey', { key: crl.key_id.slice(0, 8) }) }}</span>
                <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
                  <span>{{ t('cas.detail.crlNumber', { number: crl.crl_number }) }}</span>
                  <span>{{ t('cas.detail.crlNext', { date: date(crl.next_update) }) }}</span>
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('cas.detail.publicUrls') }}</CardTitle>
            <InfoTip :text="t('cas.detail.publicUrlsHint')" />
          </div>
        </CardHeader>
        <CardContent class="flex flex-col gap-3">
          <CaCopyField v-if="ca.urls.key_crl" :label="t('cas.detail.keyCrlUrl')" :value="ca.urls.key_crl" />
          <CaCopyField v-if="ca.urls.key_certificate" :label="t('cas.detail.keyCertificateUrl')" :value="ca.urls.key_certificate" />
          <CaCopyField :label="t('cas.detail.crlUrl')" :value="ca.urls.crl" />
          <CaCopyField :label="t('cas.detail.certificateUrl')" :value="ca.urls.certificate" />
          <CaCopyField :label="t('cas.detail.chainUrl')" :value="ca.urls.chain" />
        </CardContent>
      </Card>

      <CaHierarchyPath :ca="ca" />

      <Card v-if="ca.versions.length">
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('cas.detail.versions') }}</CardTitle>
            <InfoTip :text="t('cas.detail.versionsHint')" />
          </div>
        </CardHeader>
        <CardContent>
          <ul class="divide-y rounded-md border">
            <li v-for="version in ca.versions" :key="version.id" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
              <span class="font-medium">{{ t('cas.detail.version', { version: version.version }) }}</span>
              <Badge v-if="version.active" variant="secondary">{{ t('cas.detail.current') }}</Badge>
              <span class="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" :title="version.fingerprint_sha256">{{ colonHex(version.serial) }}</span>
              <CaExpiry :not-after="version.not_after" />
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>

    <CaImportDialog v-model:open="importOpen" :ca="ca" @imported="replace" />
    <CaRenewDialog v-model:open="renewOpen" :ca="ca" @renewed="replace" />
    <CaDisableDialog v-model:open="disableOpen" :ca="ca" @disabled="replace" />
    <CaRevokeDialog v-model:open="revokeOpen" :ca="ca" @revoked="replace" />
  </div>
</template>
