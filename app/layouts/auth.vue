<script setup lang="ts">
/**
 * Sign-in pages: the form on the left, a brand-coloured panel on the right (wide screens
 * only).
 */
const { t } = useI18n()
</script>

<template>
  <div class="grid min-h-svh bg-background lg:grid-cols-2">
    <div class="flex flex-col gap-10 px-6 py-8 md:px-10">
      <NuxtLink to="/login" class="flex h-8 items-center self-start">
        <AppLogo />
      </NuxtLink>
      <div class="flex flex-1 items-center justify-center">
        <div class="w-full max-w-sm [&>[data-slot=card]]:shadow-sm">
          <slot />
        </div>
      </div>
    </div>
    <aside class="relative hidden flex-col justify-center gap-3 overflow-hidden bg-[linear-gradient(160deg,var(--brand),color-mix(in_oklab,var(--brand)_55%,black))] px-14 text-brand-foreground lg:flex">
      <h2 class="max-w-md text-3xl font-semibold tracking-tight text-balance">{{ t('auth.tagline') }}</h2>
      <p class="max-w-md opacity-80">{{ t('auth.subline') }}</p>
    </aside>
  </div>
</template>
