<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { CertificateDetail, LeafRevocationReason } from '~/types/api'

/** Revoke a certificate with an RFC 5280 reason; it goes on its CA's CRL right away. */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ certificate: CertificateDetail; name: string }>()
const emit = defineEmits<{ revoked: [certificate: CertificateDetail] }>()
const { t } = useI18n()
const rpc = useRpc()

const REASONS: LeafRevocationReason[] = ['unspecified', 'key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation', 'privilege_withdrawn']
const reason = ref<LeafRevocationReason>('unspecified')

watch(open, (value) => {
  if (value) reason.value = 'unspecified'
})

const submit = useAction(async () => {
  const res = await rpc('certificates.revoke', { id: props.certificate.id, reason: reason.value })
  toast.success(t('certificates.revoke.revoked', { name: props.name }))
  open.value = false
  emit('revoked', res.data)
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t('certificates.revoke.title', { name }) }}</DialogTitle>
        <DialogDescription>{{ t('certificates.revoke.description') }}</DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="submit()">
        <Field>
          <FieldLabel for="revoke-reason">{{ t('revocation.reason') }}</FieldLabel>
          <Select v-model="reason">
            <SelectTrigger id="revoke-reason" class="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="value in REASONS" :key="value" :value="value">{{ t(`revocation.reasons.${value}`) }}</SelectItem>
            </SelectContent>
          </Select>
          <FieldDescription>{{ t(`revocation.hints.${reason}`) }}</FieldDescription>
        </Field>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" variant="destructive" :loading="submit.busy">{{ t('certificates.revoke.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
