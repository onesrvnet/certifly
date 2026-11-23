<script setup lang="ts">
import 'vue-sonner/style.css'

const { locale } = useI18n()

useTheme()
useHead({
  htmlAttrs: { lang: locale },
  titleTemplate: (title) => (title ? `${title} – certifly` : 'certifly'),
  script: [{ innerHTML: themeBootScript, tagPosition: 'head' }],
})
</script>

<template>
  <NuxtLoadingIndicator color="var(--primary)" :height="2" :throttle="150" />
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
  <Toaster position="bottom-right" />
</template>
