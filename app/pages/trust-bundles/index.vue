<script setup lang="ts">
import { DownloadIcon, PackageIcon, PlusIcon } from '@lucide/vue'

import type { TrustBundle } from '~/types/api'

/** Trust bundles: named sets of CA certificates, each published as one PEM file at a public URL. */
definePageMeta({ titleKey: 'nav.trustBundles', requires: ['instance', 'read_trust_bundles'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('nav.trustBundles') })

async function loadAll() {
  const all: TrustBundle[] = []
  let cursor: string | undefined
  do {
    const res = await rpc('trust_bundles.list', { cursor, limit: 200 })
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  auth.remember(all)
  return all
}

const { data: bundles, status } = await useAsyncData('trust-bundles', loadAll, { default: () => [] as TrustBundle[] })
const canCreate = computed(() => auth.can('instance', 'create_trust_bundle'))
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="max-w-2xl text-sm text-muted-foreground">{{ t('trustBundles.description') }}</p>
      <Button v-if="canCreate" as-child>
        <NuxtLink to="/trust-bundles/new"><PlusIcon />{{ t('trustBundles.create') }}</NuxtLink>
      </Button>
    </div>

    <div v-if="status === 'pending' && !bundles.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-16 w-full" />
    </div>

    <div v-else-if="!bundles.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><PackageIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('trustBundles.empty') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('trustBundles.emptyHint') }}</p>
      <Button v-if="canCreate" as-child class="mt-2">
        <NuxtLink to="/trust-bundles/new"><PlusIcon />{{ t('trustBundles.create') }}</NuxtLink>
      </Button>
    </div>

    <ul v-else class="divide-y overflow-hidden rounded-md border">
      <li v-for="bundle in bundles" :key="bundle.id" class="flex items-start gap-3 p-3 sm:px-4">
        <PackageIcon class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <NuxtLink :to="`/trust-bundles/${bundle.id}`" class="flex min-w-0 flex-1 flex-col gap-1 underline-offset-4 hover:underline">
          <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span class="truncate font-medium">{{ bundle.name }}</span>
            <span class="font-mono text-xs text-muted-foreground">{{ bundle.slug }}</span>
          </span>
          <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
            <MetaChip :label="t('trustBundles.casChip')">{{ bundle.cas.map((ca) => ca.name).join(', ') }}</MetaChip>
            <span v-if="bundle.include_chain">{{ t('trustBundles.withChain') }}</span>
          </span>
        </NuxtLink>
        <Button variant="outline" size="sm" as-child class="shrink-0">
          <a :href="bundle.path" :download="`${bundle.slug}.pem`"><DownloadIcon /><span class="sr-only sm:not-sr-only">{{ t('trustBundles.download') }}</span></a>
        </Button>
      </li>
    </ul>
  </div>
</template>
