<script setup lang="ts">
/** Read-only name constraints of a CA, grouped by permitted and excluded. */
const props = defineProps<{ constraints: { permitted: { dns: string[]; ip: string[]; email: string[] }; excluded: { dns: string[]; ip: string[]; email: string[] } } | null }>()
const { t } = useI18n()

const sides = computed(() =>
  props.constraints
    ? (['permitted', 'excluded'] as const).map((side) => ({
        side,
        groups: (['dns', 'ip', 'email'] as const).map((kind) => ({ kind, values: props.constraints![side][kind] })).filter((g) => g.values.length),
      }))
    : [],
)
const empty = computed(() => sides.value.every((s) => !s.groups.length))
</script>

<template>
  <p v-if="empty" class="text-sm text-muted-foreground">{{ t('cas.detail.noConstraints') }}</p>
  <div v-else class="grid gap-4 sm:grid-cols-2">
    <div v-for="{ side, groups } in sides" :key="side" class="flex flex-col gap-2">
      <span class="text-xs font-medium text-muted-foreground">{{ t(`cas.nc.${side}`) }}</span>
      <p v-if="!groups.length" class="text-sm text-muted-foreground">{{ t('cas.nc.none') }}</p>
      <div v-for="group in groups" :key="group.kind" class="flex flex-col gap-1">
        <span class="text-xs text-muted-foreground">{{ t(`cas.nc.${group.kind}`) }}</span>
        <ul class="flex flex-wrap gap-1.5">
          <li v-for="value in group.values" :key="value"><Badge variant="secondary" class="font-mono text-xs">{{ value }}</Badge></li>
        </ul>
      </div>
    </div>
  </div>
</template>
