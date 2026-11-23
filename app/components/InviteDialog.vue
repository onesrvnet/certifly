<script setup lang="ts">
import { CopyIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { Role } from '~/types/api'

/**
 * Invite someone by email with a role; they get a link to accept it. When the instance cannot
 * send mail, the server hands the link back instead, and it is shown here once to pass on.
 */
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ invited: [] }>()

const { t } = useI18n()
const rpc = useRpc()

const email = ref('')
const role = ref<Role>('viewer')
/** The invite link when no mail was sent. Shown once; cleared when the dialog closes. */
const link = ref<string | null>(null)

watch(open, (value) => {
  link.value = null
  if (!value) return
  email.value = ''
  role.value = 'viewer'
})

const submit = useAction(async () => {
  const address = email.value.trim().toLowerCase()
  const res = await rpc('invites.create', { email: address, role: role.value })
  emit('invited')
  if (res.data.link) {
    link.value = res.data.link
    toast.success(t('users.inviteCreated', { email: address }))
    return
  }
  toast.success(t('users.inviteSent', { email: address }))
  open.value = false
})

async function copyLink() {
  if (!link.value) return
  await navigator.clipboard.writeText(link.value)
  toast.success(t('users.inviteLinkCopied'))
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <template v-if="link">
        <DialogHeader>
          <DialogTitle>{{ t('users.inviteLinkTitle') }}</DialogTitle>
          <DialogDescription>{{ t('users.inviteLinkHint') }}</DialogDescription>
        </DialogHeader>
        <div class="flex gap-2">
          <Input :model-value="link" readonly class="font-mono text-xs" :aria-label="t('users.inviteLinkTitle')" @focus="($event.target as HTMLInputElement).select()" />
          <Button variant="outline" size="icon" class="shrink-0" :aria-label="t('common.copy')" @click="copyLink"><CopyIcon class="size-4" /></Button>
        </div>
        <DialogFooter>
          <Button @click="open = false">{{ t('common.done') }}</Button>
        </DialogFooter>
      </template>
      <template v-else>
        <DialogHeader>
          <DialogTitle>{{ t('users.inviteTitle') }}</DialogTitle>
          <DialogDescription>{{ t('users.inviteDescription') }}</DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="submit()">
          <FieldGroup>
            <Field>
              <FieldLabel for="invite-email">{{ t('auth.email') }}</FieldLabel>
              <Input id="invite-email" v-model="email" type="email" required autofocus :placeholder="t('auth.emailPlaceholder')" />
            </Field>
            <Field>
              <FieldLabel for="invite-role">{{ t('users.role') }}</FieldLabel>
              <Select v-model="role">
                <SelectTrigger id="invite-role"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="option in (['admin', 'operator', 'viewer'] as const)" :key="option" :value="option">{{ t(`roles.${option}`) }}</SelectItem>
                </SelectContent>
              </Select>
              <FieldDescription>{{ t(`roles.${role}Hint`) }}</FieldDescription>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="submit.busy" :disabled="!email.trim()">{{ t('users.sendInvite') }}</Button>
          </DialogFooter>
        </form>
      </template>
    </DialogContent>
  </Dialog>
</template>
