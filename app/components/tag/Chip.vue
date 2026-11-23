<script setup lang="ts">
/** A tag: a tinted chip with a coloured outline and dot. Slot content (e.g. a remove button) goes after the name. */
defineProps<{ name: string; color: string }>()
</script>

<template>
  <span class="inline-flex max-w-full items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium text-foreground" :style="tagStyle(color)">
    <span class="size-2 shrink-0 rounded-full bg-(--tag-tone)" aria-hidden="true" />
    <span class="truncate">{{ name }}</span>
    <slot />
  </span>
</template>
