<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { Group } from '~/types/api'

/** Create a group or change its name and description. Provider group names are edited on the group's page. */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ group: Group | null }>()
const emit = defineEmits<{ saved: [group: Group] }>()
const { t } = useI18n()
const rpc = useRpc()
const errorMessage = useErrorMessage()

const name = ref('')
const description = ref('')
const formError = ref('')

watch(open, (isOpen) => {
  formError.value = ''
  if (!isOpen) return
  name.value = props.group?.name ?? ''
  description.value = props.group?.description ?? ''
})

const submit = useAction(async () => {
  formError.value = ''
  const body = { name: name.value.trim(), description: description.value.trim() }
  try {
    const res = props.group ? await rpc('groups.update', { id: props.group.id, ...body }) : await rpc('groups.create', body)
    toast.success(t(props.group ? 'groups.dialog.saved' : 'groups.dialog.created', { name: res.data.name }))
    open.value = false
    emit('saved', res.data)
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    formError.value = errorMessage(error)
  }
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ group ? t('groups.dialog.editTitle') : t('groups.dialog.createTitle') }}</DialogTitle>
        <DialogDescription class="sr-only">{{ t('groups.dialog.createTitle') }}</DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="submit()">
        <FieldGroup>
          <Field>
            <FieldLabel for="group-name">{{ t('groups.dialog.name') }}</FieldLabel>
            <Input id="group-name" v-model="name" maxlength="100" required :placeholder="t('groups.dialog.namePlaceholder')" />
          </Field>
          <Field>
            <FieldLabel for="group-description">{{ t('groups.dialog.description') }}</FieldLabel>
            <Textarea id="group-description" v-model="description" rows="2" maxlength="1000" />
          </Field>
          <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!name.trim()">{{ group ? t('common.save') : t('groups.dialog.create') }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
