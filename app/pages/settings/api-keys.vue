<script setup lang="ts">
import { CopyIcon, KeyRoundIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { ApiKey } from '~/types/api'

definePageMeta({ titleKey: 'settings.title' })

const { t, d } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()

useHead({ title: () => t('apiKeys.title') })

const { data: keys, refresh } = await useAsyncData('api-keys', () => rpc('api_keys.list').then((res) => res.data), { default: () => [] as ApiKey[] })

// A key cannot create keys, so someone signed in with one only sees the list.
const canCreate = computed(() => !!auth.session)

const name = ref('')
const expiry = ref<'never' | '30' | '90' | '365'>('90')
/** Shown once right after creation; the server never returns it again. Cleared when the dialog closes. */
const secret = ref<string | null>(null)

const create = useAction(async () => {
  const days = expiry.value === 'never' ? null : Number(expiry.value)
  const expiresAt = days ? new Date(Date.now() + days * 86_400_000).toISOString() : null
  const res = await rpc('api_keys.create', { name: name.value.trim(), expires_at: expiresAt })
  secret.value = res.data.secret
  name.value = ''
  await refresh()
})

function onSecretOpen(open: boolean) {
  if (!open) secret.value = null
}

async function copySecret() {
  if (!secret.value) return
  await navigator.clipboard.writeText(secret.value)
  toast.success(t('apiKeys.copied'))
}

const removing = ref<ApiKey | null>(null)
async function remove() {
  const key = removing.value
  if (!key) return
  try {
    await rpc('api_keys.delete', { id: key.id })
    removing.value = null
    await refresh()
    toast.success(t('apiKeys.deleted'))
  } catch (error) {
    showError(error)
  }
}
</script>

<template>
  <SettingsSection :title="t('apiKeys.title')" :description="t('apiKeys.description')">
    <form v-if="canCreate" class="flex max-w-xl flex-col gap-3 sm:flex-row" @submit.prevent="create">
      <Input v-model="name" maxlength="100" required :placeholder="t('apiKeys.namePlaceholder')" :aria-label="t('apiKeys.name')" />
      <Select v-model="expiry">
        <SelectTrigger class="w-full sm:w-48" :aria-label="t('apiKeys.expiry')"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="30">{{ t('apiKeys.expiresIn', { days: 30 }) }}</SelectItem>
          <SelectItem value="90">{{ t('apiKeys.expiresIn', { days: 90 }) }}</SelectItem>
          <SelectItem value="365">{{ t('apiKeys.expiresIn', { days: 365 }) }}</SelectItem>
          <SelectItem value="never">{{ t('apiKeys.never') }}</SelectItem>
        </SelectContent>
      </Select>
      <Button type="submit" :loading="create.busy" :disabled="!name.trim()">{{ t('apiKeys.create') }}</Button>
    </form>

    <ul v-if="keys.length" class="max-w-xl divide-y rounded-md border">
      <li v-for="key in keys" :key="key.id" class="flex items-center gap-3 px-3 py-2.5 text-sm">
        <KeyRoundIcon class="size-4 shrink-0 text-muted-foreground" />
        <span class="flex min-w-0 flex-1 flex-col">
          <span class="truncate font-medium">{{ key.name }}</span>
          <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
            <span class="font-mono">cfy_…{{ key.last4 }}</span>
            <span>{{ key.expires_at ? t('apiKeys.expires', { date: d(new Date(key.expires_at)) }) : t('apiKeys.noExpiry') }}</span>
            <span v-if="key.last_used_at">{{ t('apiKeys.lastUsed', { date: d(new Date(key.last_used_at)) }) }}</span>
          </span>
        </span>
        <Button
          v-if="auth.can(key.id, 'delete')"
          variant="ghost"
          size="icon"
          class="size-8 text-destructive"
          :aria-label="t('apiKeys.delete')"
          :title="t('apiKeys.delete')"
          @click="removing = key"
        >
          <Trash2Icon class="size-4" />
        </Button>
      </li>
    </ul>
    <p v-else class="text-sm text-muted-foreground">{{ t('apiKeys.empty') }}</p>

    <Dialog :open="!!secret" @update:open="onSecretOpen">
      <DialogContent class="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{{ t('apiKeys.secretTitle') }}</DialogTitle>
          <DialogDescription>{{ t('apiKeys.secretHint') }}</DialogDescription>
        </DialogHeader>
        <div class="flex gap-2">
          <Input :model-value="secret ?? ''" readonly class="font-mono text-xs" :aria-label="t('apiKeys.secretTitle')" @focus="($event.target as HTMLInputElement).select()" />
          <Button variant="outline" size="icon" class="shrink-0" :aria-label="t('apiKeys.copy')" @click="copySecret"><CopyIcon class="size-4" /></Button>
        </div>
        <DialogFooter>
          <Button @click="onSecretOpen(false)">{{ t('apiKeys.done') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!removing" @update:open="(open) => !open && (removing = null)">
      <DialogContent class="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{{ t('apiKeys.deleteTitle') }}</DialogTitle>
          <DialogDescription>{{ t('apiKeys.deleteDescription', { name: removing?.name ?? '' }) }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="removing = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" @click="remove">{{ t('apiKeys.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </SettingsSection>
</template>
