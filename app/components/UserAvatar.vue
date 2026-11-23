<script setup lang="ts">
const props = defineProps<{ name?: string | null; class?: string }>()

const initials = computed(() =>
  (props.name ?? '?')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]!.toUpperCase())
    .join(''),
)
</script>

<template>
  <Avatar :class="props.class">
    <AvatarFallback class="text-xs font-medium">{{ initials }}</AvatarFallback>
  </Avatar>
</template>
