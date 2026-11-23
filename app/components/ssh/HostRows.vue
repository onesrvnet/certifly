<script setup lang="ts">
import { TriangleAlertIcon } from '@lucide/vue'

import type { SshHost } from '~/types/api'

/** The rows of a host list: name, host group, how long its certificate lasts and when it last checked in. */
defineProps<{ hosts: SshHost[]; showGroup?: boolean }>()
const { t, locale } = useI18n()

const certLeft = (host: SshHost) => (host.certificate ? approxDuration(Math.max(0, secondsUntil(host.certificate.valid_before)), t) : null)
const expired = (host: SshHost) => !!host.certificate && secondsUntil(host.certificate.valid_before) <= 0
</script>

<template>
  <ul class="divide-y overflow-hidden rounded-md border">
    <li v-for="host in hosts" :key="host.id">
      <NuxtLink :to="`/ssh/hosts/${host.id}`" class="flex flex-wrap items-center gap-x-3 gap-y-1.5 p-3 hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none sm:px-4">
        <span class="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1">
          <span class="truncate font-medium">{{ host.name }}</span>
          <Badge v-if="showGroup" variant="outline" class="text-muted-foreground">{{ host.host_group.name }}</Badge>
        </span>
        <span class="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span v-if="host.certificate" class="inline-flex items-center gap-1" :class="hostCertWarn(host.certificate.valid_before) && 'text-warning'">
            <TriangleAlertIcon v-if="hostCertWarn(host.certificate.valid_before)" class="size-3.5" />
            {{ expired(host) ? t('sshHosts.row.certExpired') : t('sshHosts.row.cert', { time: certLeft(host) }) }}
          </span>
          <span v-else>{{ t('sshHosts.row.noCert') }}</span>
          <span v-if="host.last_seen_at" class="inline-flex items-center gap-1" :class="hostSeenStale(host.last_seen_at) && 'text-warning'">
            <TriangleAlertIcon v-if="hostSeenStale(host.last_seen_at)" class="size-3.5" />
            {{ t('sshHosts.row.seen', { time: timeAgo(host.last_seen_at, locale) }) }}
          </span>
          <span v-else>{{ t('sshHosts.row.neverSynced') }}</span>
        </span>
      </NuxtLink>
    </li>
  </ul>
</template>
