<script setup lang="ts">
import { PlusIcon, UsersRoundIcon } from '@lucide/vue'

import type { Group, SshAccessRule } from '~/types/api'

/** Groups of people (admins): who is in each, which provider groups feed them, and how many host groups use them. */
definePageMeta({ titleKey: 'settings.title', requires: ['instance', 'read_groups'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('groups.title') })

async function loadAll<T>(call: (cursor: string | undefined) => Promise<{ data: T[]; next_cursor: string | null }>) {
  const all: T[] = []
  let cursor: string | undefined
  do {
    const res = await call(cursor)
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  return all
}

const { data: groups, status, refresh } = await useAsyncData(
  'groups',
  async () => {
    const all = await loadAll((cursor) => rpc('groups.list', { cursor, limit: 200 }))
    auth.remember(all)
    return all
  },
  { default: () => [] as Group[] },
)
const { data: rules } = await useLazyAsyncData('groups-rules', () => loadAll((cursor) => rpc('ssh_access_rules.list', { cursor, limit: 200 })), { default: () => [] as SshAccessRule[] })
const usedIn = (group: Group) => new Set(rules.value.filter((rule) => rule.group.id === group.id).map((rule) => rule.host_group.id)).size

const canManage = computed(() => auth.can('instance', 'manage_groups'))
const createOpen = ref(false)
</script>

<template>
  <SettingsSection :title="t('groups.title')">
    <div v-if="canManage && groups.length" class="flex justify-end">
      <Button @click="createOpen = true"><PlusIcon />{{ t('groups.new') }}</Button>
    </div>

    <div v-if="status === 'pending' && !groups.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-16 w-full" />
    </div>

    <div v-else-if="!groups.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><UsersRoundIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('groups.empty') }}</h3>
      <Button v-if="canManage" class="mt-2" @click="createOpen = true"><PlusIcon />{{ t('groups.new') }}</Button>
    </div>

    <ul v-else class="divide-y overflow-hidden rounded-md border">
      <li v-for="group in groups" :key="group.id">
        <NuxtLink :to="`/settings/groups/${group.id}`" class="flex items-start gap-3 p-3 hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none sm:px-4">
          <UsersRoundIcon class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <span class="flex min-w-0 flex-1 flex-col gap-1.5">
            <span class="truncate font-medium">{{ group.name }}</span>
            <span class="flex min-w-0 flex-wrap items-center gap-2">
              <MetaChip :label="t('groups.chips.members')">{{ group.member_count }}</MetaChip>
              <MetaChip v-if="group.provider_groups.length" :label="t('groups.chips.providerGroups')"><span class="font-mono">{{ group.provider_groups.join(', ') }}</span></MetaChip>
              <MetaChip :label="t('groups.chips.usedIn')">{{ usedIn(group) }}</MetaChip>
            </span>
          </span>
        </NuxtLink>
      </li>
    </ul>

    <GroupEditDialog v-model:open="createOpen" :group="null" @saved="refresh()" />
  </SettingsSection>
</template>
