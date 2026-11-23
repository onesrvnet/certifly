<script setup lang="ts">
import { DownloadIcon } from '@lucide/vue'

import type { CertificateDetail } from '~/types/api'

/** The certificate as PEM and DER, its chain (issuing CA up to the root) and the full bundle. */
const props = defineProps<{ certificate: Pick<CertificateDetail, 'pem' | 'chain_pem' | 'bundle_pem'>; fileName: string }>()
const { t } = useI18n()

const items = computed(() => [
  { key: 'pem', label: t('certificates.downloads.pem'), run: () => downloadText(`${props.fileName}.pem`, props.certificate.pem) },
  { key: 'der', label: t('certificates.downloads.der'), run: () => downloadBytes(`${props.fileName}.der`, pemToDer(props.certificate.pem), 'application/pkix-cert') },
  // Imported certificates come without a chain: certifly does not hold their issuer.
  ...(props.certificate.chain_pem
    ? [
        { key: 'chain', label: t('certificates.downloads.chain'), run: () => downloadText(`${props.fileName}-chain.pem`, props.certificate.chain_pem) },
        { key: 'bundle', label: t('certificates.downloads.bundle'), run: () => downloadText(`${props.fileName}-fullchain.pem`, props.certificate.bundle_pem) },
      ]
    : []),
])
</script>

<template>
  <div class="flex flex-wrap gap-2">
    <Button v-for="item in items" :key="item.key" variant="outline" size="sm" @click="item.run()"><DownloadIcon />{{ item.label }}</Button>
  </div>
</template>
