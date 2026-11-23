<script setup lang="ts">
const route = useRoute()
const { t } = useI18n()
const sidebarOpen = useCookie<boolean>('sidebar_state', { default: () => true })

const isSettings = computed(() => route.path.startsWith('/settings'))
const title = computed(() => (route.meta.titleKey ? t(route.meta.titleKey) : ''))

useHead({ title })
</script>

<template>
  <SidebarProvider :default-open="sidebarOpen">
    <SettingsSidebar v-if="isSettings" />
    <AppSidebar v-else />
    <SidebarInset class="min-w-0">
      <!-- Pages with `header: false` render their own PageHeader. -->
      <PageHeader v-if="route.meta.header !== false">
        <h1 class="truncate font-medium">{{ title }}</h1>
      </PageHeader>
      <main class="min-w-0 flex-1">
        <slot />
      </main>
    </SidebarInset>
    <ReauthDialog />
  </SidebarProvider>
</template>
