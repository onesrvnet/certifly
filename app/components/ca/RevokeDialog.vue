<script setup lang="ts">
import { TriangleAlertIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CaRevocationReason, CertificateAuthorityDetail } from '~/types/api'

/**
 * Revoke a CA. An internal CA goes on its parent's CRL; an externally signed one can only be
 * marked compromised here, and the dialog says to revoke it at the outside root as well.
 * Either way the CA is disabled.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ ca: CertificateAuthorityDetail }>()
const emit = defineEmits<{ revoked: [ca: CertificateAuthorityDetail] }>()
const { t } = useI18n()
const rpc = useRpc()

const REASONS: CaRevocationReason[] = ['unspecified', 'key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation']
const reason = ref<CaRevocationReason>('key_compromise')
const external = computed(() => props.ca.signing === 'external')
const mode = computed(() => (external.value ? 'markCompromised' : 'revoke'))

watch(open, (value) => {
  if (value) reason.value = 'key_compromise'
})

const submit = useAction(async () => {
  const res = await rpc('certificate_authorities.revoke', { id: props.ca.id, reason: reason.value })
  toast.success(t(`cas.${mode.value}.done`, { name: props.ca.name }))
  open.value = false
  emit('revoked', res.data)
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t(`cas.${mode}.title`, { name: ca.name }) }}</DialogTitle>
        <DialogDescription>{{ t(`cas.${mode}.description`, { parent: ca.parent?.name ?? '' }) }}</DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="submit()">
        <Alert v-if="external" class="border-warning/40 bg-warning-soft text-warning">
          <TriangleAlertIcon />
          <AlertDescription class="text-foreground">{{ t('cas.markCompromised.externalSteps') }}</AlertDescription>
        </Alert>
        <Field>
          <FieldLabel for="ca-revoke-reason">{{ t('revocation.reason') }}</FieldLabel>
          <Select v-model="reason">
            <SelectTrigger id="ca-revoke-reason" class="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="value in REASONS" :key="value" :value="value">{{ t(`revocation.reasons.${value}`) }}</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" variant="destructive" :loading="submit.busy">{{ t(`cas.${mode}.submit`) }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
