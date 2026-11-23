<script setup lang="ts">
/** One setting: label and description on the left, its control on the right. */
defineProps<{ label: string; description?: string; for?: string }>()
</script>

<template>
  <div class="flex flex-col gap-3 border-b py-4 last:border-b-0 sm:flex-row sm:items-center sm:justify-between sm:gap-8">
    <div class="flex min-w-0 flex-col gap-1">
      <label :for="$props.for" class="text-sm font-medium">{{ label }}</label>
      <p v-if="description" class="text-sm text-muted-foreground">{{ description }}</p>
    </div>
    <div class="flex shrink-0 items-center gap-2">
      <slot />
    </div>
  </div>
</template>
