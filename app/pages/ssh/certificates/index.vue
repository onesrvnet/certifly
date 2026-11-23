<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { KeyRoundIcon, ListFilterIcon, SearchIcon, ShieldCheckIcon, XIcon } from '@lucide/vue'

import type { SearchListItem } from '~/components/SearchListDialog.vue'
import type { SshCertificate, SshHostGroup } from '~/types/api'

/**
 * SSH certificates: user and host certificates with a search over key IDs and principals,
 * filtered by status, host group, person and host. Everyone sees their own; operators see all.
 */
definePageMeta({ titleKey: 'nav.sshCertificates' })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

useHead({ title: () => t('nav.sshCertificates') })

const PAGE_SIZE = 50
const ALL = 'all'
const KINDS = ['user', 'host'] as const
const STATUSES = ['active', 'expired', 'revoked'] as const
const VIEWS = ['all', 'user', 'host', 'revoked'] as const
type View = (typeof VIEWS)[number]

const fromQuery = (name: string, allowed: readonly string[]) => {
  const value = route.query[name]
  return typeof value === 'string' && allowed.includes(value) ? value : ALL
}
const idFromQuery = (name: string) => (typeof route.query[name] === 'string' && route.query[name] ? String(route.query[name]) : '')

const kind = ref<string>(fromQuery('kind', KINDS))
const status = ref<string>(fromQuery('status', STATUSES))
const hostGroupId = ref<string>(idFromQuery('group') || ALL)
const userId = ref(idFromQuery('person'))
const hostId = ref(idFromQuery('host'))
const search = ref(typeof route.query.q === 'string' ? route.query.q : '')
const query = refDebounced(search, 300)
const pager = useCursorPages(PAGE_SIZE)
const signOpen = ref(false)
const revoking = ref<SshCertificate | null>(null)
const revokeOpen = computed({ get: () => !!revoking.value, set: (open) => { if (!open) revoking.value = null } })

const canFilterPeople = computed(() => auth.can('instance', 'sign_ssh_for_others'))
const canFilterHosts = computed(() => auth.can('instance', 'read_ssh_hosts'))
const canFilterGroups = computed(() => auth.can('instance', 'read_ssh_host_groups'))

const { data: hostGroups } = await useAsyncData(
  'ssh-cert-filter-groups',
  async () => {
    if (!canFilterGroups.value) return []
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

// Names for the chips of a person and a host that were picked, or came with the link.
const personName = ref('')
const hostName = ref('')
if (hostId.value && canFilterHosts.value) {
  hostName.value = await rpc('ssh_hosts.get', { id: hostId.value }).then((res) => res.data.name).catch(() => '')
}

const filter = computed(() => ({
  kind: kind.value === ALL ? undefined : (kind.value as 'user' | 'host'),
  status: status.value === ALL ? undefined : (status.value as 'active' | 'expired' | 'revoked'),
  host_group_id: hostGroupId.value === ALL ? undefined : hostGroupId.value,
  user_id: userId.value || undefined,
  host_id: hostId.value || undefined,
  query: query.value.trim() || undefined,
}))
watch(filter, () => pager.reset())
watch([kind, status, hostGroupId, userId, hostId, query], () => {
  const next: Record<string, string> = {}
  if (kind.value !== ALL) next.kind = kind.value
  if (status.value !== ALL) next.status = status.value
  if (hostGroupId.value !== ALL) next.group = hostGroupId.value
  if (userId.value) next.person = userId.value
  if (hostId.value) next.host = hostId.value
  if (query.value.trim()) next.q = query.value.trim()
  router.replace({ query: next })
})

const { data, status: loading, refresh } = await useLazyAsyncData(
  'ssh-certificates',
  async () => {
    const res = await rpc('ssh_certificates.list', { ...filter.value, cursor: pager.cursor.value, limit: PAGE_SIZE })
    auth.remember(res.data)
    return res
  },
  { watch: [filter, pager.cursor] },
)
const rows = computed<SshCertificate[]>(() => data.value?.data ?? [])
const counts = computed(() => data.value?.counts)

const VIEW_FILTERS: Record<View, { kind: string; status: string }> = {
  all: { kind: ALL, status: ALL },
  user: { kind: 'user', status: ALL },
  host: { kind: 'host', status: ALL },
  revoked: { kind: ALL, status: 'revoked' },
}
const view = computed(() => VIEWS.find((v) => VIEW_FILTERS[v].kind === kind.value && VIEW_FILTERS[v].status === status.value) ?? '')
function setView(value: string) {
  const preset = VIEW_FILTERS[value as View]
  if (!preset) return
  kind.value = preset.kind
  status.value = preset.status
}

async function loadPeople(q: string): Promise<SearchListItem[]> {
  const res = await rpc('users.list', { query: q || undefined, limit: 50 })
  return res.data.map((p) => ({ id: p.id, label: p.name, detail: p.email }))
}
async function loadHosts(q: string): Promise<SearchListItem[]> {
  const res = await rpc('ssh_hosts.list', { query: q || undefined, limit: 50 })
  return res.data.map((h) => ({ id: h.id, label: h.name, detail: h.host_group.name }))
}
const personOpen = ref(false)
const hostOpen = ref(false)
const pickPerson = (item: SearchListItem) => {
  userId.value = item.id
  personName.value = item.label
}
const pickHost = (item: SearchListItem) => {
  hostId.value = item.id
  hostName.value = item.label
}

const chips = computed(() => {
  const list: { key: string; label: string; value: string; clear: () => void }[] = []
  if (status.value !== ALL) list.push({ key: 'status', label: t('sshCerts.filters.status'), value: t(`certificates.status.${status.value}`), clear: () => (status.value = ALL) })
  if (hostGroupId.value !== ALL) list.push({ key: 'group', label: t('sshCerts.filters.hostGroup'), value: hostGroups.value.find((g) => g.id === hostGroupId.value)?.name ?? '', clear: () => (hostGroupId.value = ALL) })
  if (userId.value) {
    const name = personName.value || (rows.value.find((r) => r.user?.id === userId.value)?.user as { name?: string } | null | undefined)?.name || t('sshCerts.filters.person')
    list.push({ key: 'person', label: t('sshCerts.filters.person'), value: name, clear: () => { userId.value = ''; personName.value = '' } })
  }
  if (hostId.value) list.push({ key: 'host', label: t('sshCerts.filters.host'), value: hostName.value || (rows.value.find((r) => r.host?.id === hostId.value)?.host as { name?: string } | null | undefined)?.name || t('sshCerts.filters.host'), clear: () => { hostId.value = ''; hostName.value = '' } })
  return list
})
const hasFilter = computed(() => kind.value !== ALL || status.value !== ALL || hostGroupId.value !== ALL || !!userId.value || !!hostId.value || !!search.value)
</script>

<template>
  <div class="mx-auto flex w-full max-w-6xl flex-col gap-6 p-4 md:p-10">
    <div class="flex justify-end">
      <Button @click="signOpen = true"><KeyRoundIcon />{{ t('ssh.sign.button') }}</Button>
    </div>

    <div class="-mx-4 overflow-x-auto px-4 md:mx-0 md:px-0">
      <Tabs :model-value="view" @update:model-value="(value) => setView(String(value))">
        <TabsList>
          <TabsTrigger v-for="v in VIEWS" :key="v" :value="v" class="px-3">
            {{ t(`sshCerts.views.${v}`) }}
            <span v-if="counts" class="rounded-full px-1.5 text-xs text-muted-foreground tabular-nums">{{ counts[v] }}</span>
          </TabsTrigger>
        </TabsList>
      </Tabs>
    </div>

    <div class="flex flex-col gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <div class="relative w-full sm:w-72">
          <SearchIcon class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input v-model="search" type="search" class="pl-8" :aria-label="t('common.search')" :placeholder="t('sshCerts.searchPlaceholder')" autocomplete="off" spellcheck="false" />
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <Button variant="outline"><ListFilterIcon />{{ t('sshCerts.filters.add') }}</Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" class="w-48">
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>{{ t('sshCerts.filters.status') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuRadioGroup v-model="status">
                  <DropdownMenuRadioItem :value="ALL">{{ t('sshCerts.filters.all') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="value in STATUSES" :key="value" :value="value">{{ t(`certificates.status.${value}`) }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub v-if="hostGroups.length">
              <DropdownMenuSubTrigger>{{ t('sshCerts.filters.hostGroup') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent class="max-h-72 overflow-y-auto">
                <DropdownMenuRadioGroup v-model="hostGroupId">
                  <DropdownMenuRadioItem :value="ALL">{{ t('sshCerts.filters.all') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="group in hostGroups" :key="group.id" :value="group.id">{{ group.name }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuItem v-if="canFilterPeople" @select="personOpen = true">{{ t('sshCerts.filters.person') }}</DropdownMenuItem>
            <DropdownMenuItem v-if="canFilterHosts" @select="hostOpen = true">{{ t('sshCerts.filters.host') }}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div v-if="chips.length" class="flex flex-wrap items-center gap-2">
        <span v-for="chip in chips" :key="chip.key" class="inline-flex items-center gap-1.5 rounded-full border py-0.5 pr-1 pl-2.5 text-xs">
          <span class="text-muted-foreground">{{ chip.label }}</span>
          <span class="font-medium">{{ chip.value }}</span>
          <button type="button" class="rounded-full p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground" :aria-label="t('sshCerts.filters.remove', { name: chip.label })" @click="chip.clear()"><XIcon class="size-3" /></button>
        </span>
      </div>
    </div>

    <div v-if="loading !== 'pending' && !rows.length && !hasFilter && pager.index.value === 0" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><ShieldCheckIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('sshCerts.empty') }}</h3>
    </div>
    <SshCertRows v-else :rows="rows" :loading="loading === 'pending'" @revoke="revoking = $event" />

    <div v-if="pager.index.value > 0 || data?.next_cursor" class="flex items-center justify-between text-sm text-muted-foreground">
      <span>{{ t('common.pageRange', { from: pager.offset.value + 1, to: pager.offset.value + rows.length }) }}</span>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" :disabled="pager.index.value === 0" @click="pager.previous()">{{ t('common.previous') }}</Button>
        <Button variant="outline" size="sm" :disabled="!data?.next_cursor" @click="pager.next(data?.next_cursor)">{{ t('common.next') }}</Button>
      </div>
    </div>

    <SshSignDialog v-model:open="signOpen" @signed="refresh()" />
    <SshRevokeDialog v-model:open="revokeOpen" :certificate="revoking" @revoked="refresh()" />
    <SearchListDialog v-model:open="personOpen" :title="t('sshCerts.filters.person')" :placeholder="t('personPicker.search')" :load="loadPeople" @pick="pickPerson" />
    <SearchListDialog v-model:open="hostOpen" :title="t('sshCerts.filters.host')" :placeholder="t('sshHosts.searchPlaceholder')" :load="loadHosts" @pick="pickHost" />
  </div>
</template>
