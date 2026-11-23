<script setup lang="ts">
import { CircleCheckIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateDetail, IssueResult, Template } from '~/types/api'

/**
 * Renew a certificate: same template, subject and SANs, a new serial and lifetime. The key is
 * the stored CSR's, a new CSR's, or a new key pair certifly generates; that private key is shown
 * here once and dropped when the dialog closes.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ certificate: CertificateDetail }>()
const emit = defineEmits<{ renewed: [id: string] }>()
const { t } = useI18n()
const rpc = useRpc()
const showError = useErrorToast()

const template = ref<Template | null>(null)
const key = ref<KeySourceState>(emptyKeySource('csr'))
const result = ref<IssueResult | null>(null)

watch(open, async (value) => {
  if (!value) {
    // Closing forgets the result, and with it any private key.
    const renewed = result.value?.certificate.id
    result.value = null
    key.value = emptyKeySource('csr')
    if (renewed) emit('renewed', renewed)
    return
  }
  key.value = emptyKeySource(props.certificate.has_csr ? 'reuse' : props.certificate.key_generated ? 'keygen' : 'csr', props.certificate.key_algorithm as KeySourceState['algorithm'])
  if (!props.certificate.template_id) return
  try {
    template.value = (await rpc('templates.get', { id: props.certificate.template_id })).data
  } catch (error) {
    showError(error)
  }
})

const submit = useAction(async () => {
  const res = await rpc('certificates.renew', { id: props.certificate.id, ...keySourceRequest(key.value) })
  toast.success(t('certificates.renew.done'))
  result.value = res.data
  // Without a key to hand out there is nothing more to show here.
  if (!res.data.private_key) open.value = false
})

const fileName = computed(() => certificateFileName(props.certificate.common_name ?? props.certificate.sans[0]?.value))
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ t('certificates.renew.title') }}</DialogTitle>
        <DialogDescription>{{ t('certificates.renew.description') }}</DialogDescription>
      </DialogHeader>

      <div v-if="result?.private_key" class="flex flex-col gap-4">
        <p class="flex items-center gap-2 text-sm"><CircleCheckIcon class="size-4 text-success" />{{ t('certificates.renew.done') }}</p>
        <CertPrivateKeyPanel :private-key="result.private_key" :file-name="fileName" />
        <DialogFooter>
          <Button @click="open = false">{{ t('certificates.renew.openNew') }}</Button>
        </DialogFooter>
      </div>

      <form v-else class="flex flex-col gap-4" @submit.prevent="submit()">
        <CertKeySource
          v-model="key"
          id-prefix="renew"
          :algorithms="template?.key_algorithms ?? []"
          :allow-keygen="!!template?.allow_server_keygen"
          :allow-reuse="certificate.has_csr"
        />
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!template || !keySourceReady(key)">{{ t('certificates.renew.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
