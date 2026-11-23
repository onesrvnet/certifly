<script setup lang="ts">
import { PlusIcon, ServerCogIcon } from '@lucide/vue'

import type { SshHostGroup } from '~/types/api'

/** Host groups: the SSH CA that signs for them, the host names they cover and who may log in. */
definePageMeta({ titleKey: 'nav.sshHostGroups', requires: ['instance', 'read_ssh_host_groups'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('nav.sshHostGroups') })

async function loadAll() {
  const all: SshHostGroup[] = []
  let cursor: string | undefined
  do {
    const res = await rpc('ssh_host_groups.list', { cursor, limit: 200 })
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  auth.remember(all)
  return all
}

const { data: groups, status } = await useAsyncData('ssh-host-groups', loadAll, { default: () => [] as SshHostGroup[] })
const canCreate = computed(() => auth.can('instance', 'manage_ssh_host_groups'))
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div v-if="canCreate && groups.length" class="flex justify-end">
      <Button as-child>
        <NuxtLink to="/ssh/host-groups/new"><PlusIcon />{{ t('sshHostGroups.create') }}</NuxtLink>
      </Button>
    </div>

    <div v-if="status === 'pending' && !groups.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-16 w-full" />
    </div>

    <div v-else-if="!groups.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><ServerCogIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('sshHostGroups.empty') }}</h3>
      <Button v-if="canCreate" as-child class="mt-2">
        <NuxtLink to="/ssh/host-groups/new"><PlusIcon />{{ t('sshHostGroups.create') }}</NuxtLink>
      </Button>
    </div>

    <ul v-else class="divide-y overflow-hidden rounded-md border">
      <li v-for="group in groups" :key="group.id">
        <NuxtLink :to="`/ssh/host-groups/${group.id}`" class="flex items-start gap-3 p-3 hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none sm:px-4">
          <ServerCogIcon class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <span class="flex min-w-0 flex-1 flex-col gap-1.5">
            <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span class="truncate font-medium">{{ group.name }}</span>
              <span class="font-mono text-xs text-muted-foreground">{{ group.slug }}</span>
            </span>
            <span class="flex min-w-0 flex-wrap items-center gap-2">
              <MetaChip :label="t('sshHostGroups.chips.ca')">{{ group.ca.name }}</MetaChip>
              <MetaChip v-if="group.host_patterns.length" :label="t('sshHostGroups.chips.patterns')"><span class="font-mono">{{ group.host_patterns.join(', ') }}</span></MetaChip>
              <MetaChip :label="t('sshHostGroups.chips.hosts')">{{ group.host_count }}</MetaChip>
              <MetaChip :label="t('sshHostGroups.chips.key')">{{ t(`ssh.keyPolicy.short.${group.key_policy}`) }}</MetaChip>
            </span>
          </span>
        </NuxtLink>
      </li>
    </ul>
  </div>
</template>
