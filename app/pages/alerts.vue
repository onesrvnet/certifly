<script setup lang="ts">
import { BellIcon, MailIcon, PencilIcon, PlusIcon, SendIcon, Trash2Icon, WebhookIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { AlertChannel, AlertDelivery, AlertDeliveryStatus, AlertRule, CertificateAuthority, Template } from '~/types/api'

/**
 * Alerts: rules (what to warn about), channels (where it goes) and the delivery history.
 * Admins manage rules and channels; operators see the history only.
 */
definePageMeta({ titleKey: 'nav.alerts', requires: ['instance', 'read_alert_deliveries'] })

const { t, d } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()

useHead({ title: () => t('nav.alerts') })

const canRead = computed(() => auth.can('instance', 'read_alerts'))
const canManage = computed(() => auth.can('instance', 'manage_alerts'))
const tab = ref(canRead.value ? 'rules' : 'deliveries')

async function all<T>(load: (cursor?: string) => Promise<{ data: T[]; next_cursor: string | null }>) {
  const out: T[] = []
  let cursor: string | undefined
  do {
    const res = await load(cursor)
    out.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  auth.remember(out)
  return out
}

const { data: setup, refresh: refreshSetup } = await useAsyncData(
  'alert-setup',
  async () => {
    if (!canRead.value) return { rules: [], channels: [], cas: [], templates: [] }
    const [rules, channels, cas, templates] = await Promise.all([
      all((cursor) => rpc('alert_rules.list', { cursor, limit: 200 })),
      all((cursor) => rpc('alert_channels.list', { cursor, limit: 200 })),
      all((cursor) => rpc('certificate_authorities.list', { cursor, limit: 200 })),
      all((cursor) => rpc('templates.list', { cursor, limit: 200 })),
    ])
    return { rules, channels, cas, templates }
  },
  { default: () => ({ rules: [] as AlertRule[], channels: [] as AlertChannel[], cas: [] as CertificateAuthority[], templates: [] as Template[] }) },
)

const channelName = (id: string) => setup.value.channels.find((c) => c.id === id)?.name ?? '—'

// Deliveries, newest first, paged.
const PAGE_SIZE = 50
const ALL = 'all'
const STATUSES: AlertDeliveryStatus[] = ['sent', 'retrying', 'failed', 'pending']
const status = ref<string>(ALL)
const pager = useCursorPages(PAGE_SIZE)
watch(status, () => pager.reset())
const { data: deliveries, status: loading, refresh: refreshDeliveries } = await useLazyAsyncData(
  'alert-deliveries',
  async () => {
    const res = await rpc('alert_deliveries.list', { status: status.value === ALL ? undefined : (status.value as AlertDeliveryStatus), cursor: pager.cursor.value, limit: PAGE_SIZE })
    auth.remember(res.data)
    return res
  },
  { watch: [status, pager.cursor] },
)
const rows = computed(() => deliveries.value?.data ?? [])
// Deliveries happen in the background after an action; show the latest whenever the tab opens.
watch(tab, (value) => {
  if (value === 'deliveries') refreshDeliveries()
})
const statusTone: Record<AlertDeliveryStatus, string> = {
  sent: 'border-success/30 bg-success-soft text-success',
  retrying: 'border-warning/30 bg-warning-soft text-warning',
  failed: 'border-danger/30 bg-danger-soft text-danger',
  pending: 'border-border bg-muted text-muted-foreground',
}
const subjectLink = (row: AlertDelivery) =>
  row.subject_id ? (row.subject_type === 'certificate' ? `/certificates/${row.subject_id}` : row.subject_type === 'certificate_authority' ? `/certificate-authorities/${row.subject_id}` : null) : null
const when = (value: string) => d(new Date(value), { dateStyle: 'medium', timeStyle: 'short' })

// Dialogs.
const ruleOpen = ref(false)
const editingRule = ref<AlertRule | null>(null)
const channelOpen = ref(false)
const editingChannel = ref<AlertChannel | null>(null)
function openRule(rule: AlertRule | null) {
  editingRule.value = rule
  ruleOpen.value = true
}
function openChannel(channel: AlertChannel | null) {
  editingChannel.value = channel
  channelOpen.value = true
}

const removing = ref<{ kind: 'rule' | 'channel'; id: string; name: string } | null>(null)
const remove = useAction(async () => {
  const target = removing.value
  if (!target) return
  if (target.kind === 'rule') await rpc('alert_rules.delete', { id: target.id })
  else await rpc('alert_channels.delete', { id: target.id })
  removing.value = null
  toast.success(t('alerts.deleted', { name: target.name }))
  await refreshSetup()
})

const testing = ref<string | null>(null)
const sendTest = useAction(async (channel: AlertChannel) => {
  testing.value = channel.id
  try {
    const res = await rpc('alert_channel_tests.create', { channel_id: channel.id })
    if (res.data.status === 'sent') toast.success(t('alerts.channels.testSent', { name: channel.name }))
    else toast.error(t('alerts.channels.testFailed', { error: res.data.last_error ?? '' }))
    await refreshDeliveries()
  } finally {
    testing.value = null
  }
})

const toggleRule = useAction(async (rule: AlertRule, enabled: boolean) => {
  try {
    await rpc('alert_rules.update', { id: rule.id, enabled })
    await refreshSetup()
  } catch (error) {
    await refreshSetup()
    throw error
  }
})

function onSaved() {
  refreshSetup().catch(showError)
}
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <p class="max-w-2xl text-sm text-muted-foreground">{{ t('alerts.description') }}</p>

    <Tabs v-model="tab">
      <TabsList v-if="canRead">
        <TabsTrigger value="rules">{{ t('alerts.tabs.rules') }}</TabsTrigger>
        <TabsTrigger value="channels">{{ t('alerts.tabs.channels') }}</TabsTrigger>
        <TabsTrigger value="deliveries">{{ t('alerts.tabs.deliveries') }}</TabsTrigger>
      </TabsList>

      <TabsContent v-if="canRead" value="rules" class="flex flex-col gap-4 pt-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <p class="text-sm text-muted-foreground">{{ t('alerts.rules.description') }}</p>
          <Button v-if="canManage" :disabled="!setup.channels.length" @click="openRule(null)"><PlusIcon />{{ t('alerts.rules.create') }}</Button>
        </div>
        <p v-if="canManage && !setup.channels.length" class="text-sm text-muted-foreground">{{ t('alerts.rules.channelFirst') }}</p>
        <div v-if="!setup.rules.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-12 text-center">
          <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><BellIcon class="size-6" /></span>
          <p class="max-w-md text-sm text-muted-foreground">{{ t('alerts.rules.empty') }}</p>
        </div>
        <ul v-else class="divide-y rounded-md border">
          <li v-for="rule in setup.rules" :key="rule.id" class="flex flex-wrap items-center gap-3 px-3 py-2.5 text-sm sm:px-4">
            <span class="flex min-w-0 flex-1 flex-col gap-0.5">
              <span class="truncate font-medium">{{ rule.name }}</span>
              <span class="mt-1 flex flex-wrap gap-2">
                <MetaChip :label="t('alerts.rules.eventChip')">{{ t(`alerts.events.${rule.event}`) }}</MetaChip>
                <MetaChip v-if="rule.days_before.length" :label="t('alerts.rules.daysChip')">{{ rule.days_before.join(', ') }}</MetaChip>
                <MetaChip :label="t('alerts.rules.sendsToChip')">{{ rule.channel_ids.map(channelName).join(', ') }}</MetaChip>
              </span>
            </span>
            <Switch :model-value="rule.enabled" :disabled="!auth.can(rule.id, 'update')" :aria-label="t('alerts.rules.enabled')" @update:model-value="toggleRule(rule, $event)" />
            <span class="flex gap-1">
              <Button v-if="auth.can(rule.id, 'update')" variant="ghost" size="icon" class="size-8" :aria-label="t('alerts.edit')" :title="t('alerts.edit')" @click="openRule(rule)"><PencilIcon class="size-4" /></Button>
              <Button
                v-if="auth.can(rule.id, 'delete')"
                variant="ghost"
                size="icon"
                class="size-8 text-destructive"
                :aria-label="t('alerts.delete')"
                :title="t('alerts.delete')"
                @click="removing = { kind: 'rule', id: rule.id, name: rule.name }"
              >
                <Trash2Icon class="size-4" />
              </Button>
            </span>
          </li>
        </ul>
      </TabsContent>

      <TabsContent v-if="canRead" value="channels" class="flex flex-col gap-4 pt-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <p class="text-sm text-muted-foreground">{{ t('alerts.channels.description') }}</p>
          <Button v-if="canManage" @click="openChannel(null)"><PlusIcon />{{ t('alerts.channels.create') }}</Button>
        </div>
        <p v-if="!setup.channels.length" class="rounded-lg border border-dashed px-6 py-12 text-center text-sm text-muted-foreground">{{ t('alerts.channels.empty') }}</p>
        <ul v-else class="divide-y rounded-md border">
          <li v-for="channel in setup.channels" :key="channel.id" class="flex flex-wrap items-center gap-3 px-3 py-2.5 text-sm sm:px-4">
            <component :is="channel.kind === 'email' ? MailIcon : WebhookIcon" class="size-4 shrink-0 text-muted-foreground" />
            <span class="flex min-w-0 flex-1 flex-col gap-0.5">
              <span class="truncate font-medium">{{ channel.name }}</span>
              <span class="truncate font-mono text-xs text-muted-foreground" :title="channel.url ?? channel.recipients.join(', ')">{{ channel.url ?? channel.recipients.join(', ') }}</span>
            </span>
            <span class="flex gap-1">
              <Button v-if="auth.can(channel.id, 'test')" variant="outline" size="sm" :loading="testing === channel.id" @click="sendTest(channel)"><SendIcon />{{ t('alerts.channels.test') }}</Button>
              <Button v-if="auth.can(channel.id, 'update')" variant="ghost" size="icon" class="size-8" :aria-label="t('alerts.edit')" :title="t('alerts.edit')" @click="openChannel(channel)"><PencilIcon class="size-4" /></Button>
              <Button
                v-if="auth.can(channel.id, 'delete')"
                variant="ghost"
                size="icon"
                class="size-8 text-destructive"
                :aria-label="t('alerts.delete')"
                :title="t('alerts.delete')"
                @click="removing = { kind: 'channel', id: channel.id, name: channel.name }"
              >
                <Trash2Icon class="size-4" />
              </Button>
            </span>
          </li>
        </ul>
      </TabsContent>

      <TabsContent value="deliveries" class="flex flex-col gap-4 pt-4">
        <div class="flex flex-wrap items-end justify-between gap-3">
          <p class="max-w-xl text-sm text-muted-foreground">{{ t('alerts.deliveries.description') }}</p>
          <Field class="w-full sm:w-40">
            <FieldLabel for="delivery-status">{{ t('alerts.deliveries.status') }}</FieldLabel>
            <Select v-model="status">
              <SelectTrigger id="delivery-status" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem :value="ALL">{{ t('certificates.filters.all') }}</SelectItem>
                <SelectItem v-for="value in STATUSES" :key="value" :value="value">{{ t(`alerts.deliveries.statuses.${value}`) }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </div>
        <div class="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{{ t('alerts.deliveries.alert') }}</TableHead>
                <TableHead class="w-28">{{ t('alerts.deliveries.status') }}</TableHead>
                <TableHead class="hidden md:table-cell">{{ t('alerts.deliveries.channel') }}</TableHead>
                <TableHead class="hidden sm:table-cell">{{ t('alerts.deliveries.time') }}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-if="loading === 'pending' && !rows.length">
                <TableCell colspan="4"><Skeleton class="h-4 w-full" /></TableCell>
              </TableRow>
              <TableRow v-else-if="!rows.length">
                <TableCell colspan="4" class="h-24 text-center text-muted-foreground">{{ t('alerts.deliveries.empty') }}</TableCell>
              </TableRow>
              <TableRow v-for="row in rows" :key="row.id" :class="loading === 'pending' && 'opacity-60'">
                <TableCell class="max-w-72">
                  <span class="flex min-w-0 flex-col gap-0.5">
                    <span class="truncate font-medium">
                      {{ row.test ? t('alerts.deliveries.test') : t(`alerts.events.${row.event ?? 'issued'}`) }}
                    </span>
                    <span v-if="row.threshold_days" class="text-xs text-muted-foreground">{{ t('alerts.deliveries.threshold', { days: row.threshold_days }) }}</span>
                    <NuxtLink v-if="row.subject_label && subjectLink(row)" :to="subjectLink(row)!" class="truncate text-xs text-primary underline-offset-4 hover:underline">{{ row.subject_label }}</NuxtLink>
                    <span v-if="row.rule" class="truncate text-xs text-muted-foreground">{{ row.rule.name }}</span>
                    <span v-if="row.last_error" class="text-xs break-words text-danger">{{ row.last_error }}</span>
                    <span class="text-xs text-muted-foreground sm:hidden">{{ when(row.created_at) }}</span>
                  </span>
                </TableCell>
                <TableCell>
                  <span class="flex flex-col items-start gap-0.5">
                    <Badge variant="outline" :class="statusTone[row.status]">{{ t(`alerts.deliveries.statuses.${row.status}`) }}</Badge>
                    <span class="text-xs text-muted-foreground">{{ t('alerts.deliveries.attempts', { count: row.attempts }) }}</span>
                  </span>
                </TableCell>
                <TableCell class="hidden text-sm md:table-cell">{{ row.channel?.name ?? t('alerts.deliveries.deletedChannel') }}</TableCell>
                <TableCell class="hidden text-sm whitespace-nowrap sm:table-cell">{{ when(row.created_at) }}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
        <div v-if="pager.index.value > 0 || deliveries?.next_cursor" class="flex items-center justify-between text-sm text-muted-foreground">
          <span>{{ t('common.pageRange', { from: pager.offset.value + 1, to: pager.offset.value + rows.length }) }}</span>
          <div class="flex gap-2">
            <Button variant="outline" size="sm" :disabled="pager.index.value === 0" @click="pager.previous()">{{ t('common.previous') }}</Button>
            <Button variant="outline" size="sm" :disabled="!deliveries?.next_cursor" @click="pager.next(deliveries?.next_cursor)">{{ t('common.next') }}</Button>
          </div>
        </div>
      </TabsContent>
    </Tabs>

    <AlertRuleDialog v-model:open="ruleOpen" :rule="editingRule" :channels="setup.channels" :cas="setup.cas" :templates="setup.templates" @saved="onSaved" />
    <AlertChannelDialog v-model:open="channelOpen" :channel="editingChannel" @saved="onSaved" />

    <Dialog :open="!!removing" @update:open="(value) => !value && (removing = null)">
      <DialogContent class="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{{ t('alerts.deleteTitle', { name: removing?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ removing?.kind === 'channel' ? t('alerts.deleteChannelDescription') : t('alerts.deleteRuleDescription') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="removing = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('alerts.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
