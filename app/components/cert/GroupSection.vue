<script setup lang="ts">
import { ChevronDownIcon, ChevronRightIcon } from '@lucide/vue'

import type { Certificate, CertificateFilter, CertificateGroup, CertificateSort } from '~/types/api'

/**
 * One group of the grouped certificate list: a header with the group's count and how many
 * expire soon, and its rows, loaded the first time it is opened and then page by page.
 */
const props = defineProps<{ group: CertificateGroup; filter: CertificateFilter; sort: CertificateSort; open: boolean }>()
const emit = defineEmits<{ toggle: [] }>()
const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()

/** Tag, template and CA groups carry their name; the fixed ones (untagged, imported, statuses) are named here. */
const label = computed(() => {
  const { label: name, key } = props.group
  if (name) return name
  if (key === 'untagged') return t('tags.untagged')
  if (key === 'imported') return t('certificates.sources.import')
  return t(`certificates.status.${key}`)
})

const PAGE_SIZE = 25
const rows = ref<Certificate[]>([])
const next = ref<string | null>(null)
const loaded = ref(false)
const loading = ref(false)

async function load(cursor?: string | null) {
  loading.value = true
  try {
    const res = await rpc('certificates.list', { ...props.filter, ...(props.group.filter as CertificateFilter), sort: props.sort, cursor: cursor ?? undefined, limit: PAGE_SIZE })
    auth.remember(res.data)
    rows.value = cursor ? [...rows.value, ...res.data] : res.data
    next.value = res.next_cursor
    loaded.value = true
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen && !loaded.value) load()
  },
  { immediate: true },
)
// Filters, sort or the group itself changed: what was loaded is stale.
watch(
  () => [props.filter, props.sort, props.group.count],
  () => {
    loaded.value = false
    rows.value = []
    if (props.open) load()
  },
  { deep: true },
)
</script>

<template>
  <section class="flex flex-col gap-2">
    <button
      type="button"
      class="flex w-full flex-wrap items-center gap-2 rounded-md px-1 py-1.5 text-left hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none"
      :aria-expanded="open"
      @click="emit('toggle')"
    >
      <component :is="open ? ChevronDownIcon : ChevronRightIcon" class="size-4 shrink-0 text-muted-foreground" />
      <TagDot v-if="group.color" :color="group.color" />
      <span class="font-medium">{{ label }}</span>
      <Badge variant="secondary" class="tabular-nums">{{ group.count }}</Badge>
      <span v-if="group.expiring_within_30_days" class="ml-auto text-xs text-warning">{{ t('certificates.groups.expiringSoon', { count: group.expiring_within_30_days }, group.expiring_within_30_days) }}</span>
    </button>
    <template v-if="open">
      <CertRows :rows="rows" :loading="loading" />
      <div v-if="next" class="flex justify-center">
        <Button variant="outline" size="sm" :loading="loading" @click="load(next)">{{ t('certificates.groups.more') }}</Button>
      </div>
    </template>
  </section>
</template>
