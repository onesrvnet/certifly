<script setup lang="ts">
/** A small trend line for a stat tile: one 2px line in the brand colour, the last point marked. */
const props = defineProps<{ values: number[]; label: string }>()

const W = 80
const H = 24
const PAD = 3
const points = computed(() => {
  const max = Math.max(1, ...props.values)
  const step = props.values.length > 1 ? (W - PAD * 2) / (props.values.length - 1) : 0
  return props.values.map((v, i) => [PAD + i * step, H - PAD - (v / max) * (H - PAD * 2)] as const)
})
const last = computed(() => points.value.at(-1))
</script>

<template>
  <svg :viewBox="`0 0 ${W} ${H}`" class="h-6 w-20 text-primary" role="img" :aria-label="label">
    <title>{{ label }}</title>
    <polyline :points="points.map((p) => p.join(',')).join(' ')" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    <circle v-if="last" :cx="last[0]" :cy="last[1]" r="2.5" fill="currentColor" class="stroke-card" stroke-width="1.5" />
  </svg>
</template>
