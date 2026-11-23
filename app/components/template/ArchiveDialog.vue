<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { Template } from '~/types/api'

/** Confirm archiving a template: nothing more is issued with it; what it issued stays valid. */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ template: Template }>()
const emit = defineEmits<{ archived: [template: Template] }>()
const { t } = useI18n()
const rpc = useRpc()

const submit = useAction(async () => {
  const res = await rpc('templates.archive', { id: props.template.id })
  toast.success(t('templates.archive.done', { name: props.template.name }))
  open.value = false
  emit('archived', res.data)
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t('templates.archive.title', { name: template.name }) }}</DialogTitle>
        <DialogDescription>{{ t('templates.archive.description') }}</DialogDescription>
      </DialogHeader>
      <DialogFooter>
        <Button variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
        <Button variant="destructive" :loading="submit.busy" @click="submit()">{{ t('templates.archive.submit') }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
