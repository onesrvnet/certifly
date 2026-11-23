<script setup lang="ts">
import { FileCogIcon, PlusIcon, TriangleAlertIcon } from '@lucide/vue'

import type { Template } from '~/types/api'

/** Templates: the rules every certificate is issued under, each bound to one CA. */
definePageMeta({ titleKey: 'nav.templates', requires: ['instance', 'read_templates'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('nav.templates') })

const showArchived = ref(false)

/** Every template: a single-tenant instance has a handful, so follow the cursor to the end. */
async function loadAll() {
  const all: Template[] = []
  let cursor: string | undefined
  do {
    const res = await rpc('templates.list', { cursor, limit: 200, status: showArchived.value ? undefined : 'active' })
    all.push(...res.data)
    cursor = res.next_cursor ?? undefined
  } while (cursor)
  auth.remember(all)
  return all
}

const { data: templates, status } = await useAsyncData('templates', loadAll, { default: () => [] as Template[], watch: [showArchived] })
const canCreate = computed(() => auth.can('instance', 'create_template'))
const rules = (template: Template) => [...template.allowed_dns, ...template.allowed_ips]
</script>

<template>
  <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="max-w-2xl text-sm text-muted-foreground">{{ t('templates.description') }}</p>
      <Button v-if="canCreate" as-child>
        <NuxtLink to="/templates/new"><PlusIcon />{{ t('templates.create') }}</NuxtLink>
      </Button>
    </div>

    <Label class="self-start font-normal text-muted-foreground"><Switch v-model="showArchived" />{{ t('templates.showArchived') }}</Label>

    <div v-if="status === 'pending' && !templates.length" class="flex flex-col gap-2">
      <Skeleton v-for="i in 3" :key="i" class="h-16 w-full" />
    </div>

    <div v-else-if="!templates.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><FileCogIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('templates.empty') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('templates.emptyHint') }}</p>
      <Button v-if="canCreate" as-child class="mt-2">
        <NuxtLink to="/templates/new"><PlusIcon />{{ t('templates.create') }}</NuxtLink>
      </Button>
    </div>

    <ul v-else class="divide-y overflow-hidden rounded-md border">
      <li v-for="template in templates" :key="template.id">
        <NuxtLink :to="`/templates/${template.id}`" class="flex items-start gap-3 p-3 hover:bg-accent/50 focus-visible:bg-accent/50 focus-visible:outline-none sm:px-4">
          <FileCogIcon class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <span class="flex min-w-0 flex-1 flex-col gap-1">
            <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span class="truncate font-medium">{{ template.name }}</span>
              <span class="font-mono text-xs text-muted-foreground">{{ template.slug }}</span>
            </span>
            <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
              <MetaChip :label="t('certificates.detail.issuingCa')">{{ template.ca.name }}</MetaChip>
              <span v-if="template.bound_to_root" class="inline-flex items-center gap-1 text-warning"><TriangleAlertIcon class="size-3.5" />{{ t('templates.rootCa') }}</span>
            </span>
            <span class="truncate font-mono text-xs text-muted-foreground" :title="rules(template).join(', ')">{{ rules(template).join(', ') || '—' }}</span>
          </span>
          <span class="flex shrink-0 flex-col items-end gap-1 sm:flex-row sm:items-center sm:gap-2">
            <Badge variant="outline" class="text-muted-foreground">{{ t(`templates.kinds.${template.usage_hint}`) }}</Badge>
            <Badge v-if="template.status === 'archived'" variant="outline" class="border-border bg-muted text-muted-foreground">{{ t('templates.status.archived') }}</Badge>
          </span>
        </NuxtLink>
      </li>
    </ul>
  </div>
</template>
