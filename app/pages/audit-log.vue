<script setup lang="ts">
import { DownloadIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { AuditActorType, AuditEvent, RpcInput } from '~/types/api'

/** The audit log: who did what, newest first, with filters, keyset paging and a CSV export of the current filter. */
definePageMeta({ titleKey: 'nav.auditLog' })

const { t, te, d } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()

useHead({ title: () => t('nav.auditLog') })

if (!auth.can('instance', 'read_events')) {
  throw createError({ statusCode: 403, statusMessage: 'Forbidden', fatal: true })
}

const PAGE_SIZE = 50
/** The export stops here, so one click cannot pull the whole table through the API. */
const EXPORT_LIMIT = 20_000
const ALL = 'all'

const eventName = ref<string>(ALL)
const actorType = ref<string>(ALL)
const from = ref('')
const to = ref('')
const pager = useCursorPages(PAGE_SIZE)

/** The filter as the API takes it; the export uses the same one. */
const filter = computed<Pick<RpcInput['events.list'], 'name' | 'actor_type' | 'from' | 'to'>>(() => ({
  name: eventName.value === ALL ? undefined : eventName.value,
  actor_type: actorType.value === ALL ? undefined : (actorType.value as AuditActorType),
  from: from.value ? new Date(`${from.value}T00:00:00`).toISOString() : undefined,
  to: to.value ? new Date(`${to.value}T23:59:59.999`).toISOString() : undefined,
}))

watch(filter, () => pager.reset())

const { data, status } = await useLazyAsyncData(
  'audit-log',
  async () => {
    const res = await rpc('events.list', { ...filter.value, cursor: pager.cursor.value, limit: PAGE_SIZE })
    return { events: res.data, next_cursor: res.next_cursor }
  },
  { watch: [filter, pager.cursor] },
)
const events = computed(() => data.value?.events ?? [])

const hasFilter = computed(() => eventName.value !== ALL || actorType.value !== ALL || !!from.value || !!to.value)
function clearFilter() {
  eventName.value = ALL
  actorType.value = ALL
  from.value = ''
  to.value = ''
}

const eventLabel = (name: string) => (te(`auditEvents.${name}`) ? t(`auditEvents.${name}`) : name)
const actorLabel = (event: AuditEvent) => event.actor_name ?? (event.actor_type === 'system' ? t('auditLog.system') : t(`auditLog.actorTypes.${event.actor_type}`))

/** Short facts of an entry (`from: viewer, to: admin`); never anything secret, the server only stores ids and facts. */
function details(event: AuditEvent) {
  return Object.entries(event.data)
    .map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : String(value)}`)
    .join(', ')
}

const exporting = ref(false)
async function exportCsv() {
  exporting.value = true
  try {
    const rows: AuditEvent[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('events.list', { ...filter.value, cursor, limit: 200 })
      rows.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor && rows.length < EXPORT_LIMIT)
    const csv = toCsv(
      ['time', 'actor_type', 'actor_id', 'actor_name', 'event', 'subject_type', 'subject_id', 'ip', 'data'],
      rows.map((e) => [e.created_at, e.actor_type, e.actor_id, e.actor_name, e.name, e.subject_type, e.subject_id, e.ip, e.data]),
    )
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `certifly-audit-log-${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
    toast.success(t('auditLog.exported', { count: rows.length }))
  } catch (error) {
    showError(error)
  } finally {
    exporting.value = false
  }
}
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="text-sm text-muted-foreground">{{ t('auditLog.description') }}</p>
      <Button variant="outline" :loading="exporting" @click="exportCsv"><DownloadIcon />{{ t('auditLog.exportCsv') }}</Button>
    </div>

    <div class="flex flex-wrap items-end gap-3">
      <Field class="w-full sm:w-56">
        <FieldLabel for="filter-event">{{ t('auditLog.filterEvent') }}</FieldLabel>
        <Select v-model="eventName">
          <SelectTrigger id="filter-event"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem :value="ALL">{{ t('auditLog.allEvents') }}</SelectItem>
            <SelectItem v-for="name in AUDIT_EVENT_NAMES" :key="name" :value="name">{{ eventLabel(name) }}</SelectItem>
          </SelectContent>
        </Select>
      </Field>
      <Field class="w-full sm:w-44">
        <FieldLabel for="filter-actor">{{ t('auditLog.filterActor') }}</FieldLabel>
        <Select v-model="actorType">
          <SelectTrigger id="filter-actor"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem :value="ALL">{{ t('auditLog.allActors') }}</SelectItem>
            <SelectItem v-for="type in AUDIT_ACTOR_TYPES" :key="type" :value="type">{{ t(`auditLog.actorTypes.${type}`) }}</SelectItem>
          </SelectContent>
        </Select>
      </Field>
      <Field class="w-[calc(50%-0.375rem)] sm:w-40">
        <FieldLabel for="filter-from">{{ t('auditLog.from') }}</FieldLabel>
        <Input id="filter-from" v-model="from" type="date" :max="to || undefined" />
      </Field>
      <Field class="w-[calc(50%-0.375rem)] sm:w-40">
        <FieldLabel for="filter-to">{{ t('auditLog.to') }}</FieldLabel>
        <Input id="filter-to" v-model="to" type="date" :min="from || undefined" />
      </Field>
      <Button v-if="hasFilter" variant="ghost" @click="clearFilter">{{ t('auditLog.clear') }}</Button>
    </div>

    <div class="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead class="w-44">{{ t('auditLog.time') }}</TableHead>
            <TableHead>{{ t('auditLog.actor') }}</TableHead>
            <TableHead>{{ t('auditLog.event') }}</TableHead>
            <TableHead>{{ t('auditLog.details') }}</TableHead>
            <TableHead class="w-32">{{ t('auditLog.ip') }}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <template v-if="status === 'pending' && !events.length">
            <TableRow v-for="i in 6" :key="i">
              <TableCell v-for="j in 5" :key="j"><Skeleton class="h-4 w-full" /></TableCell>
            </TableRow>
          </template>
          <TableRow v-else-if="!events.length">
            <TableCell colspan="5" class="h-24 text-center text-muted-foreground">{{ t('auditLog.empty') }}</TableCell>
          </TableRow>
          <TableRow v-for="event in events" :key="event.id" :class="status === 'pending' && 'opacity-60'">
            <TableCell class="text-sm whitespace-nowrap">
              <time :datetime="event.created_at" :title="event.created_at">{{ d(new Date(event.created_at), { dateStyle: 'medium', timeStyle: 'short' }) }}</time>
            </TableCell>
            <TableCell class="text-sm">
              <span class="font-medium">{{ actorLabel(event) }}</span>
              <Badge v-if="event.actor_type === 'api_key'" variant="outline" class="ml-2">{{ t('auditLog.actorTypes.api_key') }}</Badge>
            </TableCell>
            <TableCell class="text-sm">{{ eventLabel(event.name) }}</TableCell>
            <TableCell class="max-w-72 truncate text-xs text-muted-foreground" :title="details(event)">{{ details(event) || '—' }}</TableCell>
            <TableCell class="font-mono text-xs text-muted-foreground">{{ event.ip ?? '—' }}</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <div v-if="pager.index.value > 0 || data?.next_cursor" class="flex items-center justify-between text-sm text-muted-foreground">
      <span>{{ t('common.pageRange', { from: pager.offset.value + 1, to: pager.offset.value + events.length }) }}</span>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" :disabled="pager.index.value === 0" @click="pager.previous()">{{ t('common.previous') }}</Button>
        <Button variant="outline" size="sm" :disabled="!data?.next_cursor" @click="pager.next(data?.next_cursor)">{{ t('common.next') }}</Button>
      </div>
    </div>
  </div>
</template>
