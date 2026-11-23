<script setup lang="ts">
import { FileBadgeIcon, FileInputIcon, FilePlusIcon, ListFilterIcon, SearchIcon, SlidersHorizontalIcon, XIcon } from '@lucide/vue'
import { refDebounced } from '@vueuse/core'

import type { CertificateAuthority, CertificateFilter, CertificateGroupBy, CertificateSort, CertificateStatus, Tag, Template } from '~/types/api'

/**
 * Leaf certificates, filtered by status, origin (issued here or imported), CA, template, tags and
 * expiry, with a search over names and serials; sorted, and optionally grouped by tag, template, CA
 * or status. Operators can import certificates issued elsewhere.
 */
definePageMeta({ titleKey: 'nav.certificates', requires: ['instance', 'read_certificates'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('nav.certificates') })

const PAGE_SIZE = 50
const ALL = 'all'
const STATUSES: CertificateStatus[] = ['active', 'expired', 'superseded', 'revoked']
const EXPIRY = ['7', '30', '90'] as const
const ORIGINS = ['issued', 'imported'] as const
const SORTS: CertificateSort[] = ['newest', 'expiry', 'name']
const GROUPS: CertificateGroupBy[] = ['tag', 'template', 'ca', 'status']
const NONE = 'none'

const route = useRoute()
const router = useRouter()
/** Filters and view options live in the link, so a filtered list can be shared or bookmarked. */
const fromQuery = (name: string, allowed?: readonly string[]) => {
  const value = route.query[name]
  return typeof value === 'string' && value && (!allowed || allowed.includes(value)) ? value : ALL
}
const status = ref<string>(fromQuery('status', STATUSES))
const caId = ref<string>(fromQuery('ca'))
const templateId = ref<string>(fromQuery('template'))
const expiry = ref<string>(fromQuery('expiry', EXPIRY))
const origin = ref<string>(fromQuery('origin', ORIGINS))
const tagIds = ref<string[]>(typeof route.query.tags === 'string' && route.query.tags ? route.query.tags.split(',') : [])
const sortFromQuery = fromQuery('sort', SORTS)
const sort = ref<CertificateSort>(sortFromQuery !== ALL ? (sortFromQuery as CertificateSort) : expiry.value === ALL ? 'newest' : 'expiry')
const groupFromQuery = fromQuery('group', GROUPS)
const groupBy = ref<string>(groupFromQuery === ALL ? NONE : groupFromQuery)
const importOpen = ref(false)
const search = ref(typeof route.query.q === 'string' ? route.query.q : '')
const query = refDebounced(search, 300)
const pager = useCursorPages(PAGE_SIZE)

const [{ data: cas }, { data: templates }, { data: tags }] = await Promise.all([
  useAsyncData('certificate-filter-cas', async () => (await rpc('certificate_authorities.list', { limit: 200 })).data, { default: () => [] as CertificateAuthority[] }),
  useAsyncData('certificate-filter-templates', async () => (await rpc('templates.list', { limit: 200 })).data, { default: () => [] as Template[] }),
  useAsyncData('certificate-filter-tags', async () => (await rpc('tags.list')).data, { default: () => [] as Tag[] }),
])
const pickedTags = computed(() => tags.value.filter((tag) => tagIds.value.includes(tag.id)))

const filter = computed<CertificateFilter>(() => ({
  status: status.value === ALL ? undefined : (status.value as CertificateStatus),
  ca_id: caId.value === ALL ? undefined : caId.value,
  template_id: templateId.value === ALL ? undefined : templateId.value,
  imported: origin.value === ALL ? undefined : origin.value === 'imported',
  ...(expiry.value === ALL ? {} : { expiring_before: new Date(Date.now() + Number(expiry.value) * DAY_SECONDS * 1000).toISOString() }),
  tag_ids: tagIds.value.length ? tagIds.value : undefined,
  query: query.value.trim() || undefined,
}))
watch([filter, sort], () => pager.reset())
// Keep the link in step with what is shown; defaults are left out.
watch([status, caId, templateId, expiry, origin, tagIds, query, sort, groupBy], () => {
  const next: Record<string, string> = {}
  if (status.value !== ALL) next.status = status.value
  if (expiry.value !== ALL) next.expiry = expiry.value
  if (origin.value !== ALL) next.origin = origin.value
  if (caId.value !== ALL) next.ca = caId.value
  if (templateId.value !== ALL) next.template = templateId.value
  if (tagIds.value.length) next.tags = tagIds.value.join(',')
  if (query.value.trim()) next.q = query.value.trim()
  if (sort.value !== (expiry.value === ALL ? 'newest' : 'expiry')) next.sort = sort.value
  if (groupBy.value !== NONE) next.group = groupBy.value
  router.replace({ query: next })
})
// Looking for what runs out soon: show the soonest first.
watch(expiry, (value) => {
  if (value !== ALL) sort.value = 'expiry'
})

const grouped = computed(() => groupBy.value !== NONE)
const { data, status: loading, refresh } = await useLazyAsyncData(
  'certificates',
  async () => {
    if (grouped.value) return null
    const res = await rpc('certificates.list', { ...filter.value, sort: sort.value, cursor: pager.cursor.value, limit: PAGE_SIZE })
    auth.remember(res.data)
    return res
  },
  { watch: [filter, sort, pager.cursor, groupBy] },
)
const rows = computed(() => data.value?.data ?? [])

// Grouped view: the groups and their counts; each section loads its own rows.
const { data: groups, status: groupsLoading, refresh: refreshGroups } = await useLazyAsyncData(
  'certificate-groups',
  async () => (grouped.value ? (await rpc('certificate_groups.list', { ...filter.value, group_by: groupBy.value as CertificateGroupBy })).data : []),
  { watch: [filter, groupBy], default: () => [] },
)

/** Which groups are open, remembered per browser and grouping; the first group starts open. */
const openGroups = ref<string[]>([])
const storageKey = computed(() => `certifly-certificate-groups:${groupBy.value}`)
watch(
  [groupBy, groups],
  () => {
    if (!grouped.value || !import.meta.client) return
    let saved: string[] | null = null
    try {
      saved = JSON.parse(localStorage.getItem(storageKey.value) ?? 'null')
    } catch {
      saved = null
    }
    openGroups.value = Array.isArray(saved) ? saved : groups.value[0] ? [String(groups.value[0].key)] : []
  },
  { immediate: true },
)
function toggleGroup(key: string) {
  openGroups.value = openGroups.value.includes(key) ? openGroups.value.filter((k) => k !== key) : [...openGroups.value, key]
  try {
    localStorage.setItem(storageKey.value, JSON.stringify(openGroups.value))
  } catch {
    // Without storage the state just is not remembered.
  }
}

async function refreshAll() {
  await Promise.all([grouped.value ? refreshGroups() : refresh(), refreshCounts()])
}

/** Quick views: each sets status, expiry and origin, leaving CA, template, tags and search alone. */
const VIEWS = ['all', 'expiring', 'revoked', 'imported'] as const
type View = (typeof VIEWS)[number]
const VIEW_FILTERS: Record<View, { status: string; expiry: string; origin: string }> = {
  all: { status: ALL, expiry: ALL, origin: ALL },
  expiring: { status: 'active', expiry: '30', origin: ALL },
  revoked: { status: 'revoked', expiry: ALL, origin: ALL },
  imported: { status: ALL, expiry: ALL, origin: 'imported' },
}
/** The view the current filters match; none when they were set by hand. */
const view = computed(() => VIEWS.find((v) => VIEW_FILTERS[v].status === status.value && VIEW_FILTERS[v].expiry === expiry.value && VIEW_FILTERS[v].origin === origin.value) ?? '')
function setView(value: string) {
  const preset = VIEW_FILTERS[value as View]
  if (!preset) return
  status.value = preset.status
  expiry.value = preset.expiry
  origin.value = preset.origin
}
// Counts over all certificates, from the status and CA groupings (imported ones have no CA).
const { data: viewCounts, refresh: refreshCounts } = await useLazyAsyncData('certificate-view-counts', async () => {
  const [byStatus, byCa] = await Promise.all([rpc('certificate_groups.list', { group_by: 'status' }), rpc('certificate_groups.list', { group_by: 'ca' })])
  const count = (key: string) => byStatus.data.find((g) => g.key === key)?.count ?? 0
  return {
    all: byStatus.data.reduce((sum, g) => sum + g.count, 0),
    expiring: byStatus.data.reduce((sum, g) => sum + g.expiring_within_30_days, 0),
    revoked: count('revoked'),
    imported: byCa.data.find((g) => g.key === 'imported')?.count ?? 0,
  } satisfies Record<View, number>
})

function toggleTag(id: string) {
  tagIds.value = tagIds.value.includes(id) ? tagIds.value.filter((x) => x !== id) : [...tagIds.value, id]
}

/** The active filters as removable chips; tags get their own coloured chips. */
const chips = computed(() => {
  const list: { key: string; label: string; value: string; clear: () => void }[] = []
  if (status.value !== ALL) list.push({ key: 'status', label: t('certificates.filters.status'), value: t(`certificates.status.${status.value}`), clear: () => (status.value = ALL) })
  if (expiry.value !== ALL) list.push({ key: 'expiry', label: t('certificates.filters.expiry'), value: t('certificates.filters.within', { days: expiry.value }), clear: () => (expiry.value = ALL) })
  if (caId.value !== ALL) list.push({ key: 'ca', label: t('certificates.filters.ca'), value: cas.value.find((ca) => ca.id === caId.value)?.name ?? '', clear: () => (caId.value = ALL) })
  if (templateId.value !== ALL) list.push({ key: 'template', label: t('certificates.filters.template'), value: templates.value.find((tpl) => tpl.id === templateId.value)?.name ?? '', clear: () => (templateId.value = ALL) })
  if (origin.value !== ALL) list.push({ key: 'origin', label: t('certificates.filters.origin'), value: t(`certificates.filters.origins.${origin.value}`), clear: () => (origin.value = ALL) })
  return list
})
const viewChanged = computed(() => groupBy.value !== NONE || sort.value !== 'newest')

const hasFilter = computed(() => status.value !== ALL || caId.value !== ALL || templateId.value !== ALL || expiry.value !== ALL || origin.value !== ALL || tagIds.value.length > 0 || !!search.value)
function clearFilter() {
  status.value = ALL
  caId.value = ALL
  templateId.value = ALL
  expiry.value = ALL
  origin.value = ALL
  tagIds.value = []
  search.value = ''
}
</script>

<template>
  <div class="mx-auto flex w-full max-w-6xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="max-w-2xl text-sm text-muted-foreground">{{ t('certificates.description') }}</p>
      <div class="flex flex-wrap gap-2">
        <Button v-if="auth.can('instance', 'import_certificates')" variant="outline" @click="importOpen = true"><FileInputIcon />{{ t('certificates.import.button') }}</Button>
        <Button v-if="auth.can('instance', 'issue_certificate')" as-child>
          <NuxtLink to="/certificates/issue"><FilePlusIcon />{{ t('certificates.issueButton') }}</NuxtLink>
        </Button>
      </div>
    </div>

    <div class="-mx-4 overflow-x-auto px-4 md:mx-0 md:px-0">
      <Tabs :model-value="view" @update:model-value="(value) => setView(String(value))">
        <TabsList>
          <TabsTrigger v-for="v in VIEWS" :key="v" :value="v" class="px-3">
            {{ t(`certificates.views.${v}`) }}
            <span v-if="viewCounts" class="rounded-full px-1.5 text-xs tabular-nums" :class="v === 'expiring' && viewCounts[v] > 0 ? 'bg-warning-soft text-warning' : 'text-muted-foreground'">{{ viewCounts[v] }}</span>
          </TabsTrigger>
        </TabsList>
      </Tabs>
    </div>

    <div class="flex flex-col gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <div class="relative w-full sm:w-72">
          <SearchIcon class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input v-model="search" type="search" class="pl-8" :aria-label="t('common.search')" :placeholder="t('certificates.searchPlaceholder')" autocomplete="off" spellcheck="false" />
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <Button variant="outline"><ListFilterIcon />{{ t('certificates.filters.add') }}</Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" class="w-48">
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>{{ t('certificates.filters.status') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuRadioGroup v-model="status">
                  <DropdownMenuRadioItem :value="ALL">{{ t('certificates.filters.all') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="value in STATUSES" :key="value" :value="value">{{ t(`certificates.status.${value}`) }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>{{ t('certificates.filters.expiry') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuRadioGroup v-model="expiry">
                  <DropdownMenuRadioItem :value="ALL">{{ t('certificates.filters.anyExpiry') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="days in EXPIRY" :key="days" :value="days">{{ t('certificates.filters.within', { days }) }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub v-if="tags.length">
              <DropdownMenuSubTrigger>{{ t('tags.filter') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent class="max-h-72 overflow-y-auto">
                <DropdownMenuCheckboxItem v-for="tag in tags" :key="tag.id" :model-value="tagIds.includes(tag.id)" @select.prevent="toggleTag(tag.id)">
                  <TagDot :color="tag.color" />{{ tag.name }}
                </DropdownMenuCheckboxItem>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub v-if="cas.length">
              <DropdownMenuSubTrigger>{{ t('certificates.filters.ca') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent class="max-h-72 overflow-y-auto">
                <DropdownMenuRadioGroup v-model="caId">
                  <DropdownMenuRadioItem :value="ALL">{{ t('certificates.filters.all') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="ca in cas" :key="ca.id" :value="ca.id">{{ ca.name }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub v-if="templates.length">
              <DropdownMenuSubTrigger>{{ t('certificates.filters.template') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent class="max-h-72 overflow-y-auto">
                <DropdownMenuRadioGroup v-model="templateId">
                  <DropdownMenuRadioItem :value="ALL">{{ t('certificates.filters.all') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="tpl in templates" :key="tpl.id" :value="tpl.id">{{ tpl.name }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>{{ t('certificates.filters.origin') }}</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuRadioGroup v-model="origin">
                  <DropdownMenuRadioItem :value="ALL">{{ t('certificates.filters.all') }}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem v-for="value in ORIGINS" :key="value" :value="value">{{ t(`certificates.filters.origins.${value}`) }}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
          </DropdownMenuContent>
        </DropdownMenu>
        <Popover>
          <PopoverTrigger as-child>
            <Button variant="outline" class="ml-auto">
              <SlidersHorizontalIcon />{{ t('certificates.view.button') }}
              <span v-if="viewChanged" class="size-1.5 rounded-full bg-primary" />
            </Button>
          </PopoverTrigger>
          <PopoverContent align="end" class="flex w-64 flex-col gap-4">
            <Field>
              <FieldLabel for="cert-group">{{ t('certificates.groups.groupBy') }}</FieldLabel>
              <Select v-model="groupBy">
                <SelectTrigger id="cert-group" class="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem :value="NONE">{{ t('certificates.groups.none') }}</SelectItem>
                  <SelectItem v-for="value in GROUPS" :key="value" :value="value">{{ t(`certificates.groups.by.${value}`) }}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel for="cert-sort">{{ t('certificates.sort.label') }}</FieldLabel>
              <Select v-model="sort">
                <SelectTrigger id="cert-sort" class="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="value in SORTS" :key="value" :value="value">{{ t(`certificates.sort.${value}`) }}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </PopoverContent>
        </Popover>
      </div>

      <div v-if="chips.length || pickedTags.length" class="flex flex-wrap items-center gap-2">
        <span v-for="chip in chips" :key="chip.key" class="inline-flex items-center gap-1.5 rounded-full border py-0.5 pr-1 pl-2.5 text-xs">
          <span class="text-muted-foreground">{{ chip.label }}</span>
          <span class="font-medium">{{ chip.value }}</span>
          <button type="button" class="rounded-full p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground" :aria-label="t('certificates.filters.remove', { name: chip.label })" @click="chip.clear()"><XIcon class="size-3" /></button>
        </span>
        <TagChip v-for="tag in pickedTags" :key="tag.id" :name="tag.name" :color="tag.color">
          <button type="button" class="-mr-1 rounded-full p-0.5 opacity-70 hover:opacity-100" :aria-label="t('certificates.filters.remove', { name: tag.name })" @click="toggleTag(tag.id)"><XIcon class="size-3" /></button>
        </TagChip>
        <Button variant="ghost" size="sm" class="h-7 px-2 text-xs" @click="clearFilter">{{ t('certificates.filters.clearAll') }}</Button>
      </div>
    </div>

    <div v-if="!grouped && loading !== 'pending' && !rows.length && !hasFilter && pager.index.value === 0" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><FileBadgeIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('certificates.empty') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('certificates.emptyHint') }}</p>
    </div>

    <template v-else-if="grouped">
      <div v-if="groupsLoading === 'pending' && !groups.length" class="flex flex-col gap-2">
        <Skeleton v-for="i in 3" :key="i" class="h-8 w-full" />
      </div>
      <p v-else-if="!groups.length" class="rounded-md border px-4 py-10 text-center text-sm text-muted-foreground">{{ t('certificates.noMatches') }}</p>
      <div v-else class="flex flex-col gap-4">
        <CertGroupSection
          v-for="group in groups"
          :key="`${groupBy}:${group.key}`"
          :group="group"
          :filter="filter"
          :sort="sort"
          :open="openGroups.includes(String(group.key))"
          @toggle="toggleGroup(String(group.key))"
        />
      </div>
    </template>

    <CertRows v-else :rows="rows" :loading="loading === 'pending'" />

    <div v-if="!grouped && (pager.index.value > 0 || data?.next_cursor)" class="flex items-center justify-between text-sm text-muted-foreground">
      <span>{{ t('common.pageRange', { from: pager.offset.value + 1, to: pager.offset.value + rows.length }) }}</span>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" :disabled="pager.index.value === 0" @click="pager.previous()">{{ t('common.previous') }}</Button>
        <Button variant="outline" size="sm" :disabled="!data?.next_cursor" @click="pager.next(data?.next_cursor)">{{ t('common.next') }}</Button>
      </div>
    </div>
  
    <CertImportDialog v-model:open="importOpen" @imported="refreshAll()" />
  </div>
</template>
