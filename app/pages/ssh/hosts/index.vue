<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { ListFilterIcon, PlusIcon, SearchIcon, ServerIcon, XIcon } from '@lucide/vue'

import type { SshHost, SshHostGroup } from '~/types/api'

/** The registry of SSH hosts with the state of their certificates, filtered by search and host group. */
definePageMeta({ titleKey: 'nav.sshHosts', requires: ['instance', 'read_ssh_hosts'] })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

useHead({ title: () => t('nav.sshHosts') })

const PAGE_SIZE = 50
const ALL = 'all'

/** Filters live in the link, so a filtered list can be shared or bookmarked. */
const search = ref(typeof route.query.q === 'string' ? route.query.q : '')
const query = refDebounced(search, 300)
const groupId = ref(typeof route.query.group === 'string' && route.query.group ? route.query.group : ALL)
const pager = useCursorPages(PAGE_SIZE)
const addOpen = ref(false)

const { data: hostGroups } = await useAsyncData(
  'ssh-host-filter-groups',
  async () => {
    const all: SshHostGroup[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_host_groups.list', { cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return all
  },
  { default: () => [] as SshHostGroup[] },
)

watch([query, groupId], () => pager.reset())
watch([query, groupId], () => {
  const next: Record<string, string> = {}
  if (query.value.trim()) next.q = query.value.trim()
  if (groupId.value !== ALL) next.group = groupId.value
  router.replace({ query: next })
})

const { data, status: loading, refresh } = await useLazyAsyncData(
  'ssh-hosts',
  async () => {
    const res = await rpc('ssh_hosts.list', {
      host_group_id: groupId.value === ALL ? undefined : groupId.value,
      query: query.value.trim() || undefined,
      cursor: pager.cursor.value,
      limit: PAGE_SIZE,
    })
    auth.remember(res.data)
    return res
  },
  { watch: [query, groupId, pager.cursor] },
)
const rows = computed<SshHost[]>(() => data.value?.data ?? [])
const picked = computed(() => hostGroups.value.find((g) => g.id === groupId.value))
const hasFilter = computed(() => !!search.value || groupId.value !== ALL)
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-center gap-2">
      <div class="relative w-full sm:w-72">
        <SearchIcon class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="search" type="search" class="pl-8" :aria-label="t('common.search')" :placeholder="t('sshHosts.searchPlaceholder')" autocomplete="off" spellcheck="false" />
      </div>
      <DropdownMenu v-if="hostGroups.length">
        <DropdownMenuTrigger as-child>
          <Button variant="outline"><ListFilterIcon />{{ t('sshHosts.filters.add') }}</Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" class="w-48">
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>{{ t('sshHosts.filters.hostGroup') }}</DropdownMenuSubTrigger>
            <DropdownMenuSubContent class="max-h-72 overflow-y-auto">
              <DropdownMenuRadioGroup v-model="groupId">
                <DropdownMenuRadioItem :value="ALL">{{ t('sshHosts.filters.all') }}</DropdownMenuRadioItem>
                <DropdownMenuRadioItem v-for="group in hostGroups" :key="group.id" :value="group.id">{{ group.name }}</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
            </DropdownMenuSubContent>
          </DropdownMenuSub>
        </DropdownMenuContent>
      </DropdownMenu>
      <Button v-if="auth.can('instance', 'manage_ssh_hosts') && hostGroups.length" class="ml-auto" @click="addOpen = true"><PlusIcon />{{ t('sshHosts.add') }}</Button>
    </div>

    <div v-if="picked" class="flex flex-wrap items-center gap-2">
      <span class="inline-flex items-center gap-1.5 rounded-full border py-0.5 pr-1 pl-2.5 text-xs">
        <span class="text-muted-foreground">{{ t('sshHosts.filters.hostGroup') }}</span>
        <span class="font-medium">{{ picked.name }}</span>
        <button type="button" class="rounded-full p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground" :aria-label="t('sshHosts.filters.remove', { name: t('sshHosts.filters.hostGroup') })" @click="groupId = ALL"><XIcon class="size-3" /></button>
      </span>
    </div>

    <div v-if="loading === 'pending' && !rows.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-12 w-full" />
    </div>

    <div v-else-if="!rows.length && !hasFilter && pager.index.value === 0" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><ServerIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('sshHosts.empty') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('sshHosts.emptyHint') }}</p>
    </div>

    <p v-else-if="!rows.length" class="rounded-md border px-4 py-10 text-center text-sm text-muted-foreground">{{ t('sshHosts.noMatches') }}</p>

    <SshHostRows v-else :hosts="rows" show-group />

    <div v-if="pager.index.value > 0 || data?.next_cursor" class="flex items-center justify-between text-sm text-muted-foreground">
      <span>{{ t('common.pageRange', { from: pager.offset.value + 1, to: pager.offset.value + rows.length }) }}</span>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" :disabled="pager.index.value === 0" @click="pager.previous()">{{ t('common.previous') }}</Button>
        <Button variant="outline" size="sm" :disabled="!data?.next_cursor" @click="pager.next(data?.next_cursor)">{{ t('common.next') }}</Button>
      </div>
    </div>

    <SshHostDialog v-model:open="addOpen" :host="null" :host-groups="hostGroups" :default-host-group-id="picked?.id" @saved="refresh()" />
  </div>
</template>
