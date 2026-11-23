<script setup lang="ts">
import { GlobeIcon, LandmarkIcon, NetworkIcon, PlusIcon } from '@lucide/vue'

import type { CertificateAuthority } from '~/types/api'

/** The CA hierarchy as a tree: roots and outside roots at the top, the CAs they signed below. */
definePageMeta({ titleKey: 'nav.certificateAuthorities', requires: ['instance', 'read_certificate_authorities'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('nav.certificateAuthorities') })

/** Every CA: a tree needs all of them, so follow the cursor to the end. */
async function loadAll() {
  const all: CertificateAuthority[] = []
  let cursor: string | undefined
  do {
    const res = await rpc('certificate_authorities.list', { cursor, limit: 200 })
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  auth.remember(all)
  return all
}

const { data: cas, status } = await useAsyncData('certificate-authorities', loadAll, { default: () => [] as CertificateAuthority[] })
const rows = computed(() => caTree(cas.value))
const canCreate = computed(() => auth.can('instance', 'create_certificate_authority'))

const iconFor = (ca: CertificateAuthority) => (ca.signing === 'self_signed' ? LandmarkIcon : NetworkIcon)
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="max-w-2xl text-sm text-muted-foreground">{{ t('cas.description') }}</p>
      <Button v-if="canCreate" as-child>
        <NuxtLink to="/certificate-authorities/new"><PlusIcon />{{ t('cas.create') }}</NuxtLink>
      </Button>
    </div>

    <div v-if="status === 'pending' && !cas.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-16 w-full" />
    </div>

    <div v-else-if="!cas.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><LandmarkIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('cas.empty') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('cas.emptyHint') }}</p>
      <Button v-if="canCreate" as-child class="mt-2">
        <NuxtLink to="/certificate-authorities/new"><PlusIcon />{{ t('cas.create') }}</NuxtLink>
      </Button>
    </div>

    <ul v-else class="divide-y overflow-hidden rounded-md border">
      <!-- Rows indent by depth; --depth is read by the padding of the row inside. -->
      <li v-for="row in rows" :key="row.key" :style="{ '--depth': row.depth }">
        <div v-if="row.kind === 'outside'" class="flex items-center gap-3 py-3 pr-3 pl-[calc(0.75rem+var(--depth)*1rem)] text-sm text-muted-foreground sm:pl-[calc(1rem+var(--depth)*1.75rem)]" :title="t('cas.outsideRootHint')">
          <GlobeIcon class="size-4 shrink-0" />
          <span class="min-w-0 flex-1 truncate">{{ commonNameOf(row.subject) }}</span>
          <Badge variant="outline" class="text-muted-foreground">{{ t('cas.outsideRoot') }}</Badge>
        </div>
        <NuxtLink v-else :to="`/certificate-authorities/${row.ca.id}`" class="flex items-start gap-3 py-3 pr-3 pl-[calc(0.75rem+var(--depth)*1rem)] hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none sm:pl-[calc(1rem+var(--depth)*1.75rem)]">
          <component :is="iconFor(row.ca)" class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <span class="flex min-w-0 flex-1 flex-col gap-1">
            <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span class="truncate font-medium">{{ row.ca.name }}</span>
              <span class="font-mono text-xs text-muted-foreground">{{ row.ca.slug }}</span>
            </span>
            <span class="truncate text-xs text-muted-foreground" :title="row.ca.subject_dn">{{ row.ca.subject_dn }}</span>
            <CaExpiry v-if="row.ca.not_after" :not-after="row.ca.not_after" />
            <span v-else class="text-xs text-muted-foreground">{{ t('cas.awaitingCertificate') }}</span>
          </span>
          <span class="flex shrink-0 flex-col items-end gap-1 sm:flex-row sm:items-center sm:gap-2">
            <Badge variant="outline" class="hidden text-muted-foreground sm:inline-flex">{{ t(`cas.signing.${row.ca.signing}`) }}</Badge>
            <CaStatusBadge :status="row.ca.status" :revoked="!!row.ca.revoked_at" />
          </span>
        </NuxtLink>
      </li>
    </ul>
  </div>
</template>
