<script setup lang="ts">
import { PlusIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { OnceSecret } from '~/components/OnceSecretDialog.vue'
import type { SshJoinToken } from '~/types/api'

/**
 * The join tokens of one host group: when each expires and whether it was used. New tokens are
 * shown once with the command that enrols a host.
 */
const props = defineProps<{ hostGroup: { id: string; name: string } }>()
const { t, locale } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const duration = (seconds: number) => durationLabel(seconds, t)

const canCreate = computed(() => auth.can('instance', 'create_ssh_join_token'))

const { data: tokens, refresh } = await useAsyncData(
  `ssh-join-tokens-${props.hostGroup.id}`,
  async () => {
    const all: SshJoinToken[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_join_tokens.list', { host_group_id: props.hostGroup.id, cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    auth.remember(all)
    return all
  },
  { default: () => [] as SshJoinToken[] },
)

const stateOf = (token: SshJoinToken) => (token.used_at ? 'used' : secondsUntil(token.expires_at) <= 0 ? 'expired' : 'open')

// Create: ask for a label and how long it is valid, then show the token once.
const creating = ref(false)
const label = ref('')
const hours = ref<number | string>(24)
const secret = ref<OnceSecret | null>(null)
const ttlSeconds = computed(() => Math.round(Number(hours.value) * 3600))
const ttlValid = computed(() => Number.isFinite(ttlSeconds.value) && ttlSeconds.value >= 60 && ttlSeconds.value <= 7 * 24 * 3600)

function openCreate() {
  label.value = ''
  hours.value = 24
  creating.value = true
}

const create = useAction(async () => {
  const res = await rpc('ssh_join_tokens.create', { host_group_id: props.hostGroup.id, label: label.value.trim() || undefined, ttl_seconds: ttlSeconds.value })
  const token = res.data.token ?? ''
  const server = window.location.origin
  secret.value = {
    title: res.data.label ? t('sshJoinTokens.created.titleNamed', { label: res.data.label }) : t('sshJoinTokens.created.title'),
    fields: [{ label: t('sshJoinTokens.created.token'), value: token }],
    example: { label: t('sshJoinTokens.created.command'), value: `certifly host join --server ${server} ${token}` },
    facts: [
      { label: t('sshJoinTokens.created.valid'), value: duration(ttlSeconds.value) },
      { label: t('sshJoinTokens.created.use'), value: t('sshJoinTokens.created.singleUse') },
      { label: t('sshJoinTokens.created.hostGroup'), value: props.hostGroup.name },
    ],
  }
  creating.value = false
  await refresh()
})

const deleting = ref<SshJoinToken | null>(null)
const remove = useAction(async () => {
  if (!deleting.value) return
  await rpc('ssh_join_tokens.delete', { id: deleting.value.id })
  toast.success(t('sshJoinTokens.deleted'))
  deleting.value = null
  await refresh()
})
</script>

<template>
  <div class="flex flex-col gap-4">
    <div v-if="canCreate" class="flex justify-end">
      <Button @click="openCreate"><PlusIcon />{{ t('sshJoinTokens.new') }}</Button>
    </div>

    <p v-if="!tokens.length" class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">{{ t('sshJoinTokens.empty') }}</p>
    <ul v-else class="divide-y rounded-md border">
      <li v-for="token in tokens" :key="token.id" class="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5 text-sm">
        <span class="flex min-w-32 flex-1 flex-col">
          <span class="truncate font-medium">{{ token.label || t('sshJoinTokens.unnamed') }}</span>
          <span class="font-mono text-xs text-muted-foreground">{{ t('sshJoinTokens.ending', { last4: token.last4 }) }}</span>
        </span>
        <MetaChip v-if="token.created_by" :label="t('sshJoinTokens.createdBy')">{{ token.created_by.name }}</MetaChip>
        <MetaChip v-if="stateOf(token) === 'open'" :label="t('sshJoinTokens.expires')">{{ timeAgo(token.expires_at, locale) }}</MetaChip>
        <MetaChip v-else-if="token.used_at" :label="t('sshJoinTokens.usedBy')">{{ token.host?.name ?? timeAgo(token.used_at, locale) }}</MetaChip>
        <Badge variant="outline" :class="stateOf(token) === 'open' ? 'border-success/30 bg-success-soft text-success' : 'text-muted-foreground'">{{ t(`sshJoinTokens.state.${stateOf(token)}`) }}</Badge>
        <Button v-if="auth.can(token.id, 'delete')" variant="ghost" size="icon" class="size-8 text-destructive" :aria-label="t('sshJoinTokens.delete')" :title="t('sshJoinTokens.delete')" @click="deleting = token"><Trash2Icon class="size-4" /></Button>
      </li>
    </ul>

    <Dialog v-model:open="creating">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshJoinTokens.new') }}</DialogTitle>
          <DialogDescription class="sr-only">{{ t('sshJoinTokens.new') }}</DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="create()">
          <FieldGroup>
            <Field>
              <FieldLabel for="join-label">{{ t('sshJoinTokens.label') }}</FieldLabel>
              <Input id="join-label" v-model="label" maxlength="100" :placeholder="t('sshJoinTokens.labelPlaceholder')" />
            </Field>
            <Field>
              <div class="flex items-center gap-1.5">
                <FieldLabel for="join-ttl">{{ t('sshJoinTokens.valid') }}</FieldLabel>
                <InfoTip :text="t('sshJoinTokens.validTip')" />
              </div>
              <div class="flex items-center gap-2">
                <Input id="join-ttl" v-model="hours" type="number" min="0.02" max="168" step="any" required class="w-28" />
                <span class="text-sm text-muted-foreground">{{ t('ssh.units.hours') }}</span>
              </div>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" @click="creating = false">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="create.busy" :disabled="!ttlValid">{{ t('sshJoinTokens.create') }}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <OnceSecretDialog v-model="secret" />

    <Dialog :open="!!deleting" @update:open="(open) => !open && (deleting = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshJoinTokens.deleteTitle', { name: deleting?.label || t('sshJoinTokens.unnamed') }) }}</DialogTitle>
          <DialogDescription>{{ t('sshJoinTokens.deleteText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleting = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('sshJoinTokens.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
