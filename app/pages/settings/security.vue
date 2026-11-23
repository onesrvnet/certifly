<script setup lang="ts">
import { FingerprintIcon, MonitorIcon, PencilIcon, PlusIcon, ShieldCheckIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { Passkey, Session } from '~/types/api'

/** How you sign in: re-authentication status, passkeys and the devices you are signed in on. */
definePageMeta({ titleKey: 'settings.title' })

const { t, d, locale } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()
const passkeys = usePasskeys()

useHead({ title: () => t('settings.security.title') })

// Re-authentication
const reauthStore = useReauthStore()
const reauth = computed(() => auth.session)

// Passkeys
const { data: list } = await useAsyncData('passkeys', async () => (await rpc('passkeys.list')).data, { default: () => [] as Passkey[] })

const adding = ref(false)
async function add() {
  adding.value = true
  try {
    const created = await passkeys.register(passkeys.defaultName())
    list.value = [...list.value, created]
    toast.success(t('passkeys.added'))
  } catch (error) {
    // Adding a passkey needs a recent confirmation; once given, the browser prompt comes again.
    if (!isPasskeyCancel(error)) showError(error, add)
  } finally {
    adding.value = false
  }
}

const renaming = ref<Passkey | null>(null)
const newName = ref('')
function startRename(passkey: Passkey) {
  renaming.value = passkey
  newName.value = passkey.name
}
async function rename() {
  const passkey = renaming.value
  if (!passkey || !newName.value.trim()) return
  try {
    const updated = await rpc('passkeys.update', { id: passkey.id, name: newName.value.trim() })
    list.value = list.value.map((p) => (p.id === passkey.id ? updated.data : p))
    renaming.value = null
  } catch (error) {
    showError(error)
  }
}

const removing = ref<Passkey | null>(null)
const remove = useAction(async () => {
  const passkey = removing.value
  if (!passkey) return
  await rpc('passkeys.delete', { id: passkey.id })
  list.value = list.value.filter((p) => p.id !== passkey.id)
  removing.value = null
  toast.success(t('passkeys.removed'))
})

// Sessions
const { data: sessions } = await useAsyncData('sessions', async () => (await rpc('sessions.list')).data, { default: () => [] as Session[] })

const revoke = useAction(async (session: Session) => {
  await rpc('sessions.delete', { id: session.id })
  sessions.value = sessions.value.filter((s) => s.id !== session.id)
  toast.success(t('sessions.revoked'))
})

/** "Chrome on macOS" from a user agent; the raw string is too long to show. */
function describeAgent(ua: string | null) {
  if (!ua) return t('sessions.unknownDevice')
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : null
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : null
  return browser && os ? t('passkeys.defaultName', { browser, os }) : (browser ?? os ?? t('sessions.unknownDevice'))
}
</script>

<template>
  <div class="flex flex-col gap-10">
    <SettingsSection :title="t('reauth.title')" :description="t('reauth.description', { minutes: Math.round((reauth?.reauth_max_age_seconds ?? 600) / 60) })">
      <div class="flex flex-wrap items-center justify-between gap-3 rounded-md border px-4 py-3">
        <div class="flex items-center gap-3">
          <ShieldCheckIcon class="size-5 shrink-0" :class="reauth?.reauth_fresh ? 'text-success' : 'text-muted-foreground'" />
          <div class="flex flex-col text-sm">
            <span class="font-medium">{{ reauth?.reauth_fresh ? t('reauth.statusFresh') : t('reauth.statusStale') }}</span>
            <span v-if="reauth?.reauth_at" class="text-xs text-muted-foreground">{{ t('reauth.last', { time: timeAgo(reauth.reauth_at, locale) }) }}</span>
          </div>
        </div>
        <Button variant="outline" size="sm" @click="reauthStore.request()">{{ t('reauth.button') }}</Button>
      </div>
    </SettingsSection>

    <SettingsSection :title="t('passkeys.title')" :description="t('passkeys.description')">
      <p v-if="!passkeys.supported.value" class="text-sm text-muted-foreground">{{ t('passkeys.unsupported') }}</p>
      <div v-else>
        <Button :disabled="adding" @click="add"><PlusIcon />{{ t('passkeys.add') }}</Button>
      </div>

      <ul v-if="list.length" class="flex flex-col divide-y rounded-md border">
        <li v-for="passkey in list" :key="passkey.id" class="flex items-center gap-3 px-4 py-3">
          <FingerprintIcon class="size-5 shrink-0 text-muted-foreground" />
          <div class="flex min-w-0 flex-1 flex-col">
            <span class="truncate text-sm font-medium">{{ passkey.name }}</span>
            <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
              <span>{{ t('passkeys.created', { date: d(new Date(passkey.created_at), { dateStyle: 'medium' }) }) }}</span>
              <span>{{ passkey.last_used_at ? t('passkeys.lastUsed', { time: timeAgo(passkey.last_used_at, locale) }) : t('passkeys.neverUsed') }}</span>
            </span>
          </div>
          <Button variant="ghost" size="icon" class="size-8" :aria-label="t('passkeys.rename')" :title="t('passkeys.rename')" @click="startRename(passkey)">
            <PencilIcon class="size-4" />
          </Button>
          <Button variant="ghost" size="icon" class="size-8" :aria-label="t('passkeys.remove')" :title="t('passkeys.remove')" @click="removing = passkey">
            <Trash2Icon class="size-4" />
          </Button>
        </li>
      </ul>
      <p v-else class="rounded-md border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">{{ t('passkeys.empty') }}</p>
    </SettingsSection>

    <SettingsSection :title="t('sessions.title')" :description="t('sessions.description')">
      <ul class="flex flex-col divide-y rounded-md border">
        <li v-for="session in sessions" :key="session.id" class="flex items-center gap-3 px-4 py-3">
          <MonitorIcon class="size-5 shrink-0 text-muted-foreground" />
          <div class="flex min-w-0 flex-1 flex-col">
            <span class="flex items-center gap-2 truncate text-sm font-medium">
              {{ describeAgent(session.user_agent) }}
              <Badge v-if="session.current" variant="secondary">{{ t('sessions.current') }}</Badge>
            </span>
            <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
              <span v-if="session.ip_address">{{ t('sessions.ipAddress', { ip: session.ip_address }) }}</span>
              <span>{{ t('sessions.lastActive', { time: timeAgo(session.last_active_at, locale) }) }}</span>
            </span>
          </div>
          <Button v-if="!session.current" variant="outline" size="sm" :loading="revoke.busy" @click="revoke(session)">{{ t('sessions.revoke') }}</Button>
        </li>
      </ul>
    </SettingsSection>

    <Dialog :open="!!renaming" @update:open="(open) => !open && (renaming = null)">
      <DialogContent class="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{{ t('passkeys.rename') }}</DialogTitle>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="rename">
          <Input v-model="newName" maxlength="100" autofocus :aria-label="t('passkeys.name')" />
          <DialogFooter>
            <Button type="button" variant="outline" @click="renaming = null">{{ t('common.cancel') }}</Button>
            <Button type="submit" :disabled="!newName.trim()">{{ t('common.save') }}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!removing" @update:open="(open) => !open && (removing = null)">
      <DialogContent class="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{{ t('passkeys.removeTitle') }}</DialogTitle>
          <DialogDescription>{{ t('passkeys.removeDescription', { name: removing?.name ?? '' }) }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="removing = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('passkeys.remove') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
