<script setup lang="ts">
/**
 * Active certificates expiring per week, as bars from the baseline. Each bar has a tooltip; a
 * visually hidden table carries the same numbers for screen readers.
 */
const props = defineProps<{ weeks: { start: string; count: number }[] }>()
const { t, d } = useI18n()

const max = computed(() => Math.max(1, ...props.weeks.map((w) => w.count)))
const week = (start: string) => d(new Date(start), { month: 'short', day: 'numeric' })
const ticks = computed(() => {
  const n = props.weeks.length
  return n ? [0, Math.floor((n - 1) / 2), n - 1] : []
})
</script>

<template>
  <div class="flex flex-col gap-2">
    <div class="relative flex h-32 items-end gap-0.5 border-b" aria-hidden="true">
      <span class="pointer-events-none absolute top-0 left-0 text-xs text-muted-foreground tabular-nums">{{ max }}</span>
      <TooltipProvider :delay-duration="0">
        <Tooltip v-for="w in weeks" :key="w.start">
          <TooltipTrigger as-child>
            <div class="group flex h-full flex-1 cursor-default items-end px-0.5">
              <div
                class="w-full rounded-t-[4px] transition-opacity group-hover:opacity-80"
                :class="w.count ? 'bg-primary' : 'bg-border'"
                :style="{ height: w.count ? `${Math.max(4, (w.count / max) * 100)}%` : '2px' }"
              />
            </div>
          </TooltipTrigger>
          <TooltipContent>{{ t('dashboard.expiry.tooltip', { count: w.count, date: week(w.start) }, w.count) }}</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
    <div class="flex text-xs text-muted-foreground" aria-hidden="true">
      <span v-for="(i, n) in ticks" :key="i" class="flex-1" :class="n === 1 ? 'text-center' : n === 2 ? 'text-right' : ''">{{ week(weeks[i]!.start) }}</span>
    </div>
    <table class="sr-only">
      <caption>{{ t('dashboard.expiry.title') }}</caption>
      <thead><tr><th>{{ t('dashboard.expiry.week') }}</th><th>{{ t('dashboard.expiry.count') }}</th></tr></thead>
      <tbody><tr v-for="w in weeks" :key="w.start"><td>{{ week(w.start) }}</td><td>{{ w.count }}</td></tr></tbody>
    </table>
  </div>
</template>
