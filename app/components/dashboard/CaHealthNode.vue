<script setup lang="ts">
import type { Dashboard } from '~/types/api'

/**
 * One CA in the dashboard's CA health tree, drawn like the Hierarchy card on a CA's page: dots
 * joined by lines, each CA's health as chips under its name, and the CAs it signed below.
 */
export interface CaHealthTreeNode {
  ca: Dashboard['cas'][number]
  children: CaHealthTreeNode[]
}

defineProps<{ node: CaHealthTreeNode; root?: boolean; last?: boolean }>()
const { t } = useI18n()
</script>

<template>
  <li class="relative" :class="{ 'pl-6': !root, 'pb-3': !root && !last }">
    <!-- The line from the parent down past this CA (to the next sibling) or into its branch only (last child). -->
    <span v-if="!root" class="absolute top-0 left-[0.4375rem] w-px bg-border" :class="last ? 'h-3' : 'bottom-0'" aria-hidden="true" />
    <span v-if="!root" class="absolute top-3 left-[0.4375rem] h-px w-4 bg-border" aria-hidden="true" />
    <div class="relative flex gap-3">
      <span v-if="node.children.length" class="absolute top-4 -bottom-3 left-[0.4375rem] w-px bg-border" aria-hidden="true" />
      <span
        class="relative mt-1 shrink-0 rounded-full border-2 border-muted-foreground/60"
        :class="root ? 'size-3.5 bg-muted-foreground/60' : 'size-3 bg-background'"
        aria-hidden="true"
      />
      <div class="flex min-w-0 flex-1 flex-col gap-1.5 text-sm">
        <div class="flex flex-wrap items-center gap-2">
          <NuxtLink :to="`/certificate-authorities/${node.ca.id}`" class="font-medium text-primary underline-offset-4 hover:underline">{{ node.ca.name }}</NuxtLink>
          <CaStatusBadge v-if="node.ca.status !== 'active'" :status="node.ca.status" />
          <CaExpiry v-else :not-after="node.ca.not_after" relative />
        </div>
        <div class="flex flex-wrap gap-1.5">
          <MetaChip :label="t('dashboard.cas.certificates')">{{ node.ca.active_certificates }}</MetaChip>
          <MetaChip v-if="node.ca.expiring_within_30_days" :label="t('dashboard.cas.expiring')"><span class="text-warning">{{ node.ca.expiring_within_30_days }}</span></MetaChip>
          <MetaChip v-if="node.ca.crl_state !== 'none'" :label="t('dashboard.cas.crl')">
            <span :class="node.ca.crl_state === 'late' ? 'text-danger' : 'text-success'">{{ t(`dashboard.cas.crlState.${node.ca.crl_state}`) }}</span>
          </MetaChip>
        </div>
      </div>
    </div>
    <ul v-if="node.children.length" class="mt-3 flex flex-col">
      <CaHealthNode v-for="(child, i) in node.children" :key="child.ca.id" :node="child" :last="i === node.children.length - 1" />
    </ul>
  </li>
</template>
