<script setup lang="ts">
/**
 * One section of a form as a card: an optional step number, the title, an optional InfoTip for
 * the whole section, then the fields.
 */
defineProps<{ title: string; step?: number; info?: string }>()
</script>

<template>
  <Card>
    <CardHeader>
      <div class="flex min-w-0 items-center gap-2">
        <span v-if="step" class="flex size-6 shrink-0 items-center justify-center rounded-full bg-brand-soft text-xs font-semibold text-primary tabular-nums">{{ step }}</span>
        <CardTitle class="min-w-0 break-words">{{ title }}</CardTitle>
        <InfoTip v-if="info" :text="info" />
      </div>
    </CardHeader>
    <CardContent>
      <slot />
    </CardContent>
  </Card>
</template>
