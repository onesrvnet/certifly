<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { CertificateAuthorityDetail } from '~/types/api'

/**
 * Renew a CA. A root or intermediate gets a new certificate for the same key (the validity is
 * asked for, and an intermediate's must end before its parent's); an externally signed CA gets
 * a new key and CSR instead.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ ca: CertificateAuthorityDetail }>()
const emit = defineEmits<{ renewed: [ca: CertificateAuthorityDetail] }>()
const { t, d } = useI18n()
const rpc = useRpc()

const DAY_MS = 24 * 60 * 60 * 1000
const external = computed(() => props.ca.signing === 'external')
const parentEnd = computed(() => (props.ca.parent?.not_after ? new Date(props.ca.parent.not_after) : null))

/** The current lifetime, but never past the parent's end. */
function defaultDays() {
  const cert = props.ca.active_certificate
  let days = cert ? Math.round((new Date(cert.not_after).getTime() - new Date(cert.not_before).getTime()) / DAY_MS) : 365
  if (parentEnd.value) days = Math.min(days, Math.floor((parentEnd.value.getTime() - Date.now()) / DAY_MS) - 1)
  return Math.max(1, days)
}

const days = ref(365)
watch(open, (value) => {
  if (value) days.value = defaultDays()
})

const submit = useAction(async () => {
  const res = await rpc('certificate_authorities.renew', external.value ? { id: props.ca.id } : { id: props.ca.id, validity_days: days.value })
  toast.success(external.value ? t('cas.renew.csrCreated') : t('cas.renew.renewed', { name: props.ca.name }))
  open.value = false
  emit('renewed', res.data)
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t('cas.renew.title', { name: ca.name }) }}</DialogTitle>
        <DialogDescription>
          <template v-if="external">{{ t('cas.renew.descriptionExternal') }}</template>
          <template v-else-if="ca.parent && parentEnd">{{ t('cas.renew.descriptionInternal', { parent: ca.parent.name, date: d(parentEnd, { dateStyle: 'medium' }) }) }}</template>
          <template v-else>{{ t('cas.renew.description') }}</template>
        </DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="submit()">
        <Field v-if="!external">
          <FieldLabel for="renew-days">{{ t('cas.renew.validity') }}</FieldLabel>
          <Input id="renew-days" v-model.number="days" type="number" min="1" max="36500" required />
        </Field>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!external && !(days >= 1)">{{ external ? t('cas.renew.submitExternal') : t('cas.renew.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
