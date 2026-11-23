<script setup lang="ts">
import { ChevronLeftIcon, KeyRoundIcon, ShieldIcon, SlidersHorizontalIcon, TagIcon, UserIcon, UsersIcon, UsersRoundIcon } from '@lucide/vue'
import type { Component } from 'vue'

import { useSidebar } from '~/components/ui/sidebar'

const { t } = useI18n()
const route = useRoute()
const auth = useAuthStore()
const { isMobile, setOpenMobile } = useSidebar()

const sections = computed<{ label: string; items: { to: string; label: string; icon: Component }[] }[]>(() => [
  {
    label: t('settings.account'),
    items: [
      { to: '/settings/profile', label: t('settings.profile.title'), icon: UserIcon },
      { to: '/settings/security', label: t('settings.security.title'), icon: ShieldIcon },
      { to: '/settings/api-keys', label: t('apiKeys.title'), icon: KeyRoundIcon },
    ],
  },
  ...(auth.can('instance', 'manage_users') || auth.can('instance', 'read_settings') || auth.can('instance', 'read_groups')
    ? [
        {
          label: t('settings.instance'),
          items: [
            ...(auth.can('instance', 'manage_users') ? [{ to: '/settings/users', label: t('users.title'), icon: UsersIcon }] : []),
            ...(auth.can('instance', 'read_groups') ? [{ to: '/settings/groups', label: t('groups.title'), icon: UsersRoundIcon }] : []),
            ...(auth.can('instance', 'manage_tags') ? [{ to: '/settings/tags', label: t('tags.title'), icon: TagIcon }] : []),
            ...(auth.can('instance', 'read_settings') ? [{ to: '/settings/general', label: t('settings.general.title'), icon: SlidersHorizontalIcon }] : []),
          ],
        },
      ]
    : []),
])

watch(() => route.fullPath, () => {
  if (isMobile.value) setOpenMobile(false)
})
</script>

<template>
  <Sidebar collapsible="icon">
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem class="flex items-center gap-1">
          <SidebarMenuButton as-child :tooltip="t('settings.back')" class="flex-1">
            <NuxtLink to="/">
              <ChevronLeftIcon />
              <span>{{ t('settings.back') }}</span>
            </NuxtLink>
          </SidebarMenuButton>
          <SidebarTrigger class="shrink-0 text-muted-foreground group-data-[collapsible=icon]:hidden" :title="t('nav.toggleSidebar')" :aria-label="t('nav.toggleSidebar')" />
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarHeader>

    <SidebarContent>
      <SidebarGroup v-for="section in sections" :key="section.label">
        <SidebarGroupLabel>{{ section.label }}</SidebarGroupLabel>
        <SidebarMenu>
          <SidebarMenuItem v-for="item in section.items" :key="item.to">
            <SidebarMenuButton as-child :is-active="route.path === item.to || route.path.startsWith(`${item.to}/`)" :tooltip="item.label">
              <NuxtLink :to="item.to">
                <component :is="item.icon" />
                <span>{{ item.label }}</span>
              </NuxtLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarGroup>
    </SidebarContent>

    <SidebarFooter>
      <NavUser />
    </SidebarFooter>
    <SidebarRail />
  </Sidebar>
</template>
