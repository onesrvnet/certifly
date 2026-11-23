<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <section class="flex flex-col gap-6">
    <header class="flex flex-col gap-1">
      <h2 class="text-lg font-semibold tracking-tight">{{ title }}</h2>
      <p v-if="description" class="text-sm text-muted-foreground">{{ description }}</p>
    </header>
    <slot />
  </section>
</template>
