<script setup lang="ts">
/**
 * Where a signed-in person lands when a page needs a permission they lack. A page of its own
 * rather than a thrown error, so a direct visit renders normally inside the app shell, with a
 * 403 status for the browser.
 */
definePageMeta({ titleKey: 'errorPage.forbiddenTitle' })

const { t } = useI18n()

useHead({ title: () => t('errorPage.forbiddenTitle') })
if (import.meta.server) setResponseStatus(useRequestEvent()!, 403)
</script>

<template>
  <div class="flex min-h-[calc(100svh-3.5rem)] items-center justify-center bg-background px-6 py-16">
    <div class="flex max-w-md flex-col items-center gap-4 text-center">
      <p class="error-code select-none text-[7rem] leading-none font-bold tracking-tight md:text-[9rem]" aria-hidden="true">403</p>
      <h1 class="text-2xl font-semibold tracking-tight">{{ t('errorPage.forbiddenTitle') }}</h1>
      <p class="text-muted-foreground">{{ t('errorPage.forbiddenText') }}</p>
      <Button class="mt-2" as-child>
        <NuxtLink to="/">{{ t('errorPage.goHome') }}</NuxtLink>
      </Button>
    </div>
  </div>
</template>

<style scoped>
/* Same outlined status code as the error page. */
.error-code {
  color: transparent;
  -webkit-text-stroke: 2px var(--primary);
  background: linear-gradient(180deg, var(--brand-soft), transparent 80%);
  -webkit-background-clip: text;
  background-clip: text;
}
</style>
