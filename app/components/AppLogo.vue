<script setup lang="ts">
// `*-dark` files use dark ink (for light backgrounds), `*-light` files white ink (for dark
// ones). Served from public/ by path: imported, Vite makes them absolute URLs in the browser
// only, which differ from the server's and break hydration. There is no wordmark file, so the
// name is set in text next to the mark.
defineProps<{ variant?: 'logo' | 'icon' }>()
</script>

<template>
  <span class="inline-flex h-full items-center gap-2">
    <img src="/brand/certifly-icon-dark.svg" alt="" class="h-full w-auto dark:hidden">
    <img src="/brand/certifly-icon-light.svg" alt="" class="hidden h-full w-auto dark:block">
    <span v-if="variant !== 'icon'" class="text-lg leading-none font-semibold tracking-tight">certifly</span>
    <span v-else class="sr-only">certifly</span>
  </span>
</template>
