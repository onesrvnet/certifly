<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { LeafRevocationReason, SshCertificate } from '~/types/api'

/** Revoke an SSH certificate with a reason; it goes on its CA's revocation list right away. */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ certificate: SshCertificate | null }>()
const emit = defineEmits<{ revoked: [] }>()
const { t } = useI18n()
const rpc = useRpc()

const REASONS: LeafRevocationReason[] = ['unspecified', 'key_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation', 'privilege_withdrawn']
const reason = ref<LeafRevocationReason>('unspecified')

watch(open, (value) => {
  if (value) reason.value = 'unspecified'
})

const submit = useAction(async () => {
  if (!props.certificate) return
  await rpc('ssh_certificates.revoke', { id: props.certificate.id, reason: reason.value })
  toast.success(t('sshCerts.revoke.revoked'))
  open.value = false
  emit('revoked')
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t('sshCerts.revoke.title') }}</DialogTitle>
        <DialogDescription>{{ t('sshCerts.revoke.description', { keyId: certificate?.key_id ?? '' }) }}</DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="submit()">
        <Field>
          <FieldLabel for="ssh-revoke-reason">{{ t('revocation.reason') }}</FieldLabel>
          <Select v-model="reason">
            <SelectTrigger id="ssh-revoke-reason" class="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="value in REASONS" :key="value" :value="value">{{ t(`revocation.reasons.${value}`) }}</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" variant="destructive" :loading="submit.busy">{{ t('sshCerts.revoke.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
