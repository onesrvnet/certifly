<script setup lang="ts">
/** Just the coloured dot of a tag, for pickers and group headers. */
defineProps<{ color: string }>()
</script>

<template>
  <span class="inline-block size-2.5 shrink-0 rounded-full bg-(--tag-tone)" :style="tagTone(color)" aria-hidden="true" />
</template>
