<script setup lang="ts">
import { PencilIcon, UsbIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { SshSecurityKey } from '~/types/api'

/**
 * Registered SSH security keys (YubiKeys) with rename and revoke. Without `user` it lists the
 * signed-in person's own; admins pass a person to see and revoke theirs.
 */
const props = defineProps<{ user?: { id: string; name: string } }>()

const { t, d, locale } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()

// Not awaited: the list also opens in a dialog, after the page has rendered.
const { data: keys, status } = useAsyncData(
  `ssh-security-keys-${props.user?.id ?? 'own'}`,
  async () => (await rpc('ssh_security_keys.list', props.user ? { user_id: props.user.id } : {})).data,
  { default: () => [] as SshSecurityKey[] },
)

/** `SHA256:Qk7v…x2Fo`: enough to compare with ssh-keygen -l; the full one is in the tooltip. */
function shortFingerprint(fingerprint: string) {
  const [prefix, hash = ''] = fingerprint.split(':')
  return hash.length > 12 ? `${prefix}:${hash.slice(0, 4)}…${hash.slice(-4)}` : fingerprint
}

function revokedLine(key: SshSecurityKey) {
  const date = d(new Date(key.revoked_at!), { dateStyle: 'medium' })
  if (key.revoked_by?.id === auth.user?.id) return t('sshSecurityKeys.revokedByYou', { date })
  return t('sshSecurityKeys.revokedBy', { date, name: key.revoked_by?.name ?? '—' })
}

const renaming = ref<SshSecurityKey | null>(null)
const newName = ref('')
function startRename(key: SshSecurityKey) {
  renaming.value = key
  newName.value = key.name
}
async function rename() {
  const key = renaming.value
  if (!key || !newName.value.trim()) return
  try {
    const updated = await rpc('ssh_security_keys.update', { id: key.id, name: newName.value.trim() })
    keys.value = keys.value.map((k) => (k.id === key.id ? updated.data : k))
    renaming.value = null
  } catch (error) {
    showError(error)
  }
}

const revoking = ref<SshSecurityKey | null>(null)
const revoke = useAction(async () => {
  const key = revoking.value
  if (!key) return
  const updated = await rpc('ssh_security_keys.revoke', { id: key.id })
  // Revoked keys move below the active ones, as the server orders them.
  keys.value = [...keys.value.filter((k) => k.id !== key.id && !k.revoked_at), updated.data, ...keys.value.filter((k) => k.id !== key.id && k.revoked_at)]
  revoking.value = null
  toast.success(t('sshSecurityKeys.revokedToast'))
})
</script>

<template>
  <ul v-if="keys.length" class="flex flex-col divide-y rounded-md border">
    <li v-for="key in keys" :key="key.id" class="flex items-center gap-3 px-4 py-3">
      <UsbIcon class="size-5 shrink-0" :class="key.revoked_at ? 'text-muted-foreground/50' : 'text-muted-foreground'" />
      <div class="flex min-w-0 flex-1 flex-col gap-0.5">
        <span class="flex flex-wrap items-center gap-2 text-sm font-medium" :class="key.revoked_at && 'text-muted-foreground'">
          <span class="truncate">{{ key.name }}</span>
          <Badge v-if="key.revoked_at" variant="outline" class="border-danger/30 bg-danger-soft text-danger">{{ t('sshSecurityKeys.revoked') }}</Badge>
          <Badge v-else-if="key.attested" variant="outline" class="border-success/30 bg-success-soft text-success">{{ t('sshSecurityKeys.genuine') }}</Badge>
        </span>
        <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
          <span>{{ key.model ?? t('sshSecurityKeys.securityKey') }}</span>
          <span class="font-mono" :title="key.fingerprint">{{ shortFingerprint(key.fingerprint) }}</span>
          <template v-if="key.revoked_at">
            <span>{{ revokedLine(key) }}</span>
          </template>
          <template v-else>
            <span>{{ t('sshSecurityKeys.registered', { date: d(new Date(key.created_at), { dateStyle: 'medium' }) }) }}</span>
            <span>{{ key.last_used_at ? t('sshSecurityKeys.lastUsed', { time: timeAgo(key.last_used_at, locale) }) : t('sshSecurityKeys.neverUsed') }}</span>
          </template>
        </span>
      </div>
      <Button v-if="key.permissions.update" variant="ghost" size="icon" class="size-8" :aria-label="t('sshSecurityKeys.rename')" :title="t('sshSecurityKeys.rename')" @click="startRename(key)">
        <PencilIcon class="size-4" />
      </Button>
      <Button v-if="key.permissions.revoke" variant="outline" size="sm" @click="revoking = key">{{ t('sshSecurityKeys.revoke') }}</Button>
    </li>
  </ul>
  <div v-else-if="status === 'pending'" class="h-20 animate-pulse rounded-md border bg-muted/40" />
  <p v-else class="rounded-md border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
    {{ props.user ? t('sshSecurityKeys.emptyUser', { name: props.user.name }) : t('sshSecurityKeys.empty') }}
  </p>

  <Dialog :open="!!renaming" @update:open="(open) => !open && (renaming = null)">
    <DialogContent class="sm:max-w-sm">
      <DialogHeader>
        <DialogTitle>{{ t('sshSecurityKeys.rename') }}</DialogTitle>
        <DialogDescription class="sr-only">{{ t('sshSecurityKeys.name') }}</DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="rename">
        <Input v-model="newName" maxlength="100" autofocus :aria-label="t('sshSecurityKeys.name')" />
        <DialogFooter>
          <Button type="button" variant="outline" @click="renaming = null">{{ t('common.cancel') }}</Button>
          <Button type="submit" :disabled="!newName.trim()">{{ t('common.save') }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <Dialog :open="!!revoking" @update:open="(open) => !open && (revoking = null)">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ t('sshSecurityKeys.revokeTitle', { name: revoking?.name ?? '' }) }}</DialogTitle>
        <DialogDescription>{{ t('sshSecurityKeys.revokeDescription', revoking?.active_certificates ?? 0) }}</DialogDescription>
      </DialogHeader>
      <DialogFooter>
        <Button variant="outline" @click="revoking = null">{{ t('common.cancel') }}</Button>
        <Button variant="destructive" :loading="revoke.busy" @click="revoke()">{{ t('sshSecurityKeys.revokeConfirm') }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
