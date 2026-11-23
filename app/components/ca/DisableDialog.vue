<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { CertificateAuthorityDetail } from '~/types/api'

/** Confirm taking a CA out of service; its public material stays published. */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ ca: CertificateAuthorityDetail }>()
const emit = defineEmits<{ disabled: [ca: CertificateAuthorityDetail] }>()
const { t } = useI18n()
const rpc = useRpc()

const submit = useAction(async () => {
  const res = await rpc('certificate_authorities.archive', { id: props.ca.id })
  toast.success(t('cas.disable.disabled', { name: props.ca.name }))
  open.value = false
  emit('disabled', res.data)
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t('cas.disable.title', { name: ca.name }) }}</DialogTitle>
        <DialogDescription>{{ t('cas.disable.description') }}</DialogDescription>
      </DialogHeader>
      <DialogFooter>
        <Button variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
        <Button variant="destructive" :loading="submit.busy" @click="submit()">{{ t('cas.disable.submit') }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
