<script setup lang="ts">
import { BellOffIcon, CircleCheckIcon, ClockIcon, FileBadgeIcon, FilePlusIcon, FileWarningIcon, LandmarkIcon } from '@lucide/vue'

import type { CaHealthTreeNode } from '~/components/dashboard/CaHealthNode.vue'
import type { Dashboard } from '~/types/api'

/**
 * What needs attention first, then the numbers, what expires in the coming weeks, each CA's
 * health and the latest activity.
 */
definePageMeta({ titleKey: 'nav.dashboard' })

const { t, te, locale } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

const canRead = computed(() => auth.can('instance', 'read_certificates'))
const canReadEvents = computed(() => auth.can('instance', 'read_events'))

const { data } = await useAsyncData(
  'dashboard',
  async () => {
    if (!canRead.value) return null
    return (await rpc('dashboard.get')).data
  },
  { default: () => null as Dashboard | null },
)

const empty = computed(() => !!data.value && data.value.cas.length === 0 && data.value.stats.active === 0)

const tiles = computed(() => {
  const stats = data.value?.stats
  if (!stats) return []
  return [
    { key: 'active', value: stats.active, tone: '', to: { path: '/certificates', query: { status: 'active' } }, trend: data.value!.issued_per_week },
    { key: 'expiring30', value: stats.expiring_within_30_days, tone: stats.expiring_within_30_days ? 'text-warning' : '', to: { path: '/certificates', query: { status: 'active', expiry: '30' } } },
    { key: 'revoked', value: stats.revoked, tone: '', to: { path: '/certificates', query: { status: 'revoked' } } },
    { key: 'activeCas', value: stats.active_cas, tone: '', to: { path: '/certificate-authorities' } },
  ]
})

type Attention = Dashboard['attention'][number]
const DAY_MS = 24 * 60 * 60 * 1000
function attentionView(item: Attention) {
  switch (item.kind) {
    case 'certificate_expiring': {
      const urgent = new Date(item.not_after).getTime() - Date.now() < 7 * DAY_MS
      return { icon: ClockIcon, tone: urgent ? 'text-danger' : 'text-warning', to: `/certificates/${item.id}`, text: t('dashboard.attention.certificateExpiring', { time: timeAgo(item.not_after, locale.value) }), renew: `/certificates/${item.id}?renew=1` }
    }
    case 'ca_expiring':
      return { icon: LandmarkIcon, tone: 'text-warning', to: `/certificate-authorities/${item.id}`, text: t('dashboard.attention.caExpiring', { time: timeAgo(item.not_after, locale.value) }) }
    case 'crl_late':
      return { icon: FileWarningIcon, tone: 'text-danger', to: `/certificate-authorities/${item.id}`, text: t('dashboard.attention.crlLate', { time: timeAgo(item.next_update, locale.value) }) }
    case 'delivery_failed':
      return { icon: BellOffIcon, tone: 'text-danger', to: '/alerts', text: t('dashboard.attention.deliveryFailed', { time: timeAgo(item.at, locale.value) }) }
  }
}
const attentionName = (item: Attention) => (item.kind === 'delivery_failed' ? (item.name ?? t('dashboard.attention.deletedChannel')) : item.name)

/** CAs as a tree: each root with the CAs it signed below it. */
const caRoots = computed(() => {
  const cas = data.value?.cas ?? []
  const build = (parent: string | null): CaHealthTreeNode[] => cas.filter((c) => (c.parent_ca_id ?? null) === parent).map((ca) => ({ ca, children: build(ca.id) }))
  const roots = build(null)
  // A CA whose parent is not listed (none expected) still shows, as a root.
  const shown = new Set<string>()
  const walk = (nodes: CaHealthTreeNode[]) => nodes.forEach((n) => (shown.add(n.ca.id), walk(n.children)))
  walk(roots)
  return [...roots, ...cas.filter((ca) => !shown.has(ca.id)).map((ca) => ({ ca, children: build(ca.id) }))]
})

type Activity = Dashboard['activity'][number]
/** Where an activity entry's subject lives in the app; null for subjects without a page. */
const SUBJECT_PAGES: Record<string, string> = { certificate: '/certificates/', certificate_authority: '/certificate-authorities/', template: '/templates/', trust_bundle: '/trust-bundles/' }
const subjectLink = (event: Activity) => (event.subject_id && event.subject_type && SUBJECT_PAGES[event.subject_type] ? `${SUBJECT_PAGES[event.subject_type]}${event.subject_id}` : null)
const eventLabel = (name: string) => (te(`auditEvents.${name}`) ? t(`auditEvents.${name}`) : name)
const actorLabel = (event: Activity) => event.actor_name ?? (event.actor_type === 'system' ? t('auditLog.system') : t(`auditLog.actorTypes.${event.actor_type}`))
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="flex flex-col gap-1">
        <h2 class="text-2xl font-semibold tracking-tight">{{ t('dashboard.welcome', { name: auth.user?.name ?? '' }) }}</h2>
        <p class="text-muted-foreground">{{ t('dashboard.signedInAs', { role: t(`roles.${auth.user?.role ?? 'viewer'}`) }) }}</p>
      </div>
      <Button v-if="auth.can('instance', 'issue_certificate') && !empty" as-child>
        <NuxtLink to="/certificates/issue"><FilePlusIcon />{{ t('certificates.issueButton') }}</NuxtLink>
      </Button>
    </div>

    <div v-if="!data || empty" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><FileBadgeIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('dashboard.emptyTitle') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('dashboard.emptyText') }}</p>
    </div>

    <template v-else>
      <Card>
        <CardHeader>
          <CardTitle>{{ t('dashboard.attention.title') }}</CardTitle>
        </CardHeader>
        <CardContent>
          <p v-if="!data.attention.length" class="flex items-center gap-2 text-sm text-muted-foreground">
            <CircleCheckIcon class="size-4 text-success" />{{ t('dashboard.attention.none') }}
          </p>
          <ul v-else class="divide-y rounded-md border">
            <li v-for="item in data.attention" :key="`${item.kind}:${item.id}`" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
              <component :is="attentionView(item).icon" class="size-4 shrink-0" :class="attentionView(item).tone" />
              <NuxtLink :to="attentionView(item).to" class="min-w-40 flex-1 truncate font-medium hover:underline">{{ attentionName(item) }}</NuxtLink>
              <span class="text-xs" :class="attentionView(item).tone">{{ attentionView(item).text }}</span>
              <Button v-if="attentionView(item).renew && auth.can('instance', 'issue_certificate')" variant="outline" size="sm" class="h-7" as-child>
                <NuxtLink :to="attentionView(item).renew!">{{ t('dashboard.attention.renew') }}</NuxtLink>
              </Button>
            </li>
          </ul>
        </CardContent>
      </Card>

      <section class="grid grid-cols-2 gap-3 lg:grid-cols-4" :aria-label="t('dashboard.numbers')">
        <NuxtLink
          v-for="tile in tiles"
          :key="tile.key"
          :to="tile.to"
          class="flex flex-col gap-1 rounded-lg border bg-card p-4 transition-colors hover:bg-accent/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <span class="flex items-end justify-between gap-2">
            <span class="text-3xl font-semibold tabular-nums" :class="tile.tone">{{ tile.value }}</span>
            <DashboardSparkline v-if="tile.trend" :values="tile.trend" :label="t('dashboard.tiles.issuedTrend', { values: tile.trend.join(', ') })" />
          </span>
          <span class="text-sm text-muted-foreground">{{ t(`dashboard.tiles.${tile.key}`) }}</span>
        </NuxtLink>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>{{ t('dashboard.expiry.title') }}</CardTitle>
          <CardAction>
            <Button variant="ghost" size="sm" as-child><NuxtLink :to="{ path: '/certificates', query: { status: 'active', expiry: '90' } }">{{ t('dashboard.expiry.open') }}</NuxtLink></Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          <DashboardExpiryChart :weeks="data.expiry_weeks" />
        </CardContent>
      </Card>

      <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{{ t('dashboard.cas.title') }}</CardTitle>
            <CardAction>
              <Button variant="ghost" size="sm" as-child><NuxtLink to="/certificate-authorities">{{ t('dashboard.cas.all') }}</NuxtLink></Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <ul class="flex flex-col gap-5">
              <DashboardCaHealthNode v-for="node in caRoots" :key="node.ca.id" :node="node" root />
            </ul>
          </CardContent>
        </Card>

        <Card v-if="canReadEvents">
          <CardHeader>
            <CardTitle>{{ t('dashboard.activity.title') }}</CardTitle>
            <CardAction>
              <Button variant="ghost" size="sm" as-child><NuxtLink to="/audit-log">{{ t('dashboard.activity.all') }}</NuxtLink></Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <p v-if="!data.activity.length" class="text-sm text-muted-foreground">{{ t('dashboard.activity.none') }}</p>
            <ul v-else class="flex flex-col gap-3">
              <li v-for="event in data.activity" :key="event.id" class="flex items-start gap-2 text-sm">
                <span class="flex min-w-0 flex-1 flex-col">
                  <span class="truncate"><span class="font-medium">{{ actorLabel(event) }}</span>&nbsp;<span class="text-muted-foreground">{{ eventLabel(event.name) }}</span></span>
                  <template v-if="event.subject_name">
                    <NuxtLink v-if="subjectLink(event)" :to="subjectLink(event)!" class="truncate font-mono text-xs text-muted-foreground hover:text-foreground hover:underline">{{ event.subject_name }}</NuxtLink>
                    <span v-else class="truncate font-mono text-xs text-muted-foreground">{{ event.subject_name }}</span>
                  </template>
                </span>
                <time :datetime="event.created_at" :title="event.created_at" class="shrink-0 text-xs text-muted-foreground">{{ timeAgo(event.created_at, locale) }}</time>
              </li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </template>
  </div>
</template>
