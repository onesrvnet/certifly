<script setup lang="ts">
import { KeySquareIcon, PlusIcon } from '@lucide/vue'

import type { SshCa } from '~/types/api'

/** SSH certificate authorities: the keys that sign user and host certificates. */
definePageMeta({ titleKey: 'nav.sshCas', requires: ['instance', 'read_ssh_cas'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('nav.sshCas') })

async function loadAll() {
  const all: SshCa[] = []
  let cursor: string | undefined
  do {
    const res = await rpc('ssh_cas.list', { cursor, limit: 200 })
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  auth.remember(all)
  return all
}

const { data: cas, status } = await useAsyncData('ssh-cas', loadAll, { default: () => [] as SshCa[] })
const canCreate = computed(() => auth.can('instance', 'create_ssh_ca'))
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div v-if="canCreate && cas.length" class="flex justify-end">
      <Button as-child>
        <NuxtLink to="/ssh/cas/new"><PlusIcon />{{ t('sshCas.create') }}</NuxtLink>
      </Button>
    </div>

    <div v-if="status === 'pending' && !cas.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-16 w-full" />
    </div>

    <div v-else-if="!cas.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><KeySquareIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('sshCas.empty') }}</h3>
      <Button v-if="canCreate" as-child class="mt-2">
        <NuxtLink to="/ssh/cas/new"><PlusIcon />{{ t('sshCas.create') }}</NuxtLink>
      </Button>
    </div>

    <ul v-else class="divide-y overflow-hidden rounded-md border">
      <li v-for="ca in cas" :key="ca.id">
        <NuxtLink :to="`/ssh/cas/${ca.id}`" class="flex items-start gap-3 p-3 hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none sm:px-4">
          <KeySquareIcon class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <span class="flex min-w-0 flex-1 flex-col gap-1.5">
            <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span class="truncate font-medium">{{ ca.name }}</span>
              <span class="font-mono text-xs text-muted-foreground">{{ ca.slug }}</span>
            </span>
            <span class="flex min-w-0 flex-wrap items-center gap-2">
              <MetaChip :label="t('sshCas.chips.key')">{{ sshKeyLabel(ca.key_algorithm) }}</MetaChip>
              <MetaChip :label="t('sshCas.chips.hostGroups')">{{ ca.host_group_count }}</MetaChip>
              <MetaChip :label="t('sshCas.chips.source')">{{ t(`sshCas.source.${ca.source}`) }}</MetaChip>
            </span>
          </span>
        </NuxtLink>
      </li>
    </ul>
  </div>
</template>
