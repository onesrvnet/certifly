<script setup lang="ts">
import { CopyIcon, DownloadIcon, KeyRoundIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { IssueResult } from '~/types/api'

/**
 * The private key certifly generated, shown this once. certifly does not keep it; the parent
 * drops it from its state when the person leaves.
 */
const props = defineProps<{ privateKey: NonNullable<IssueResult['private_key']>; fileName: string }>()
const { t } = useI18n()

function download() {
  if (props.privateKey.format === 'pem') downloadText(`${props.fileName}.key`, props.privateKey.pem)
  else downloadBytes(`${props.fileName}.p12`, base64ToBytes(props.privateKey.pkcs12_base64), 'application/x-pkcs12')
}

async function copy() {
  if (props.privateKey.format !== 'pem') return
  await navigator.clipboard.writeText(props.privateKey.pem)
  toast.success(t('common.copied'))
}
</script>

<template>
  <section class="flex flex-col gap-3 rounded-lg border border-warning/40 bg-warning-soft p-4" :aria-label="t('certificates.privateKey.title')">
    <div class="flex items-start gap-3">
      <KeyRoundIcon class="mt-0.5 size-5 shrink-0 text-warning" />
      <div class="flex min-w-0 flex-col gap-1">
        <h3 class="font-medium text-warning">{{ t('certificates.privateKey.title') }}</h3>
        <p class="text-sm">{{ privateKey.format === 'pem' ? t('certificates.privateKey.oncePem') : t('certificates.privateKey.oncePkcs12') }}</p>
      </div>
    </div>
    <Textarea
      v-if="privateKey.format === 'pem'"
      :model-value="privateKey.pem"
      readonly
      rows="6"
      spellcheck="false"
      class="bg-background font-mono text-xs"
      :aria-label="t('certificates.privateKey.title')"
      @focus="($event.target as HTMLTextAreaElement).select()"
    />
    <div class="flex flex-wrap gap-2">
      <Button @click="download"><DownloadIcon />{{ privateKey.format === 'pem' ? t('certificates.privateKey.downloadPem') : t('certificates.privateKey.downloadPkcs12') }}</Button>
      <Button v-if="privateKey.format === 'pem'" variant="outline" class="bg-background" @click="copy"><CopyIcon />{{ t('common.copy') }}</Button>
    </div>
  </section>
</template>
