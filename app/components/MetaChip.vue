<script setup lang="ts">
/**
 * A labelled fact shown as a small outlined chip, e.g. "Template  Web": the label muted, the
 * value in the slot (plain text or a link). Used instead of separator dots between facts.
 */
defineProps<{ label: string }>()
</script>

<template>
  <span class="inline-flex max-w-full min-w-0 items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs">
    <span class="shrink-0 text-muted-foreground">{{ label }}</span>
    <span class="min-w-0 truncate font-medium text-foreground"><slot /></span>
  </span>
</template>
