<script setup lang="ts">
import { BellIcon, FileBadgeIcon, FileCogIcon, HistoryIcon, HomeIcon, KeyRoundIcon, KeySquareIcon, LandmarkIcon, PackageIcon, ServerCogIcon, ServerIcon, SettingsIcon, ShieldCheckIcon } from '@lucide/vue'
import type { Component } from 'vue'

import { useSidebar } from '~/components/ui/sidebar'

const { t } = useI18n()
const route = useRoute()
const auth = useAuthStore()
const { isMobile, setOpenMobile } = useSidebar()

interface NavItem {
  to: string
  label: string
  icon: Component
  exact?: boolean
}

// Only pages that exist, and only for people who may read them. The first group has no label.
const groups = computed<{ key: string; label?: string; items: NavItem[] }[]>(() => {
  const shown = (items: (NavItem | false)[]) => items.filter((item): item is NavItem => !!item)
  return [
    { key: 'home', items: [{ to: '/', label: t('nav.dashboard'), icon: HomeIcon, exact: true }] },
    {
      key: 'pki',
      label: t('nav.groupPki'),
      items: shown([
        auth.can('instance', 'read_certificate_authorities') && { to: '/certificate-authorities', label: t('nav.certificateAuthorities'), icon: LandmarkIcon },
        auth.can('instance', 'read_templates') && { to: '/templates', label: t('nav.templates'), icon: FileCogIcon },
        auth.can('instance', 'read_certificates') && { to: '/certificates', label: t('nav.certificates'), icon: FileBadgeIcon },
        auth.can('instance', 'read_trust_bundles') && { to: '/trust-bundles', label: t('nav.trustBundles'), icon: PackageIcon },
      ]),
    },
    {
      key: 'ssh',
      label: t('nav.groupSsh'),
      items: shown([
        { to: '/ssh/access', label: t('nav.sshAccess'), icon: KeyRoundIcon },
        auth.can('instance', 'read_ssh_host_groups') && { to: '/ssh/host-groups', label: t('nav.sshHostGroups'), icon: ServerCogIcon },
        auth.can('instance', 'read_ssh_hosts') && { to: '/ssh/hosts', label: t('nav.sshHosts'), icon: ServerIcon },
        auth.can('instance', 'read_ssh_certificates') && { to: '/ssh/certificates', label: t('nav.sshCertificates'), icon: ShieldCheckIcon },
        auth.can('instance', 'read_ssh_cas') && { to: '/ssh/cas', label: t('nav.sshCas'), icon: KeySquareIcon },
      ]),
    },
    {
      key: 'ops',
      items: shown([
        auth.can('instance', 'read_alert_deliveries') && { to: '/alerts', label: t('nav.alerts'), icon: BellIcon },
        auth.can('instance', 'read_events') && { to: '/audit-log', label: t('nav.auditLog'), icon: HistoryIcon },
      ]),
    },
  ].filter((group) => group.items.length)
})

const isActive = (to: string, exact?: boolean) => (exact ? route.path === to : route.path.startsWith(to))

// The mobile sidebar is a sheet: close it after navigating.
watch(() => route.fullPath, () => {
  if (isMobile.value) setOpenMobile(false)
})
</script>

<template>
  <Sidebar collapsible="icon">
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton as-child size="lg" :tooltip="t('app.name')">
            <NuxtLink to="/">
              <span class="h-6 group-data-[collapsible=icon]:hidden"><AppLogo /></span>
              <span class="hidden h-6 group-data-[collapsible=icon]:block"><AppLogo variant="icon" /></span>
            </NuxtLink>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarHeader>

    <SidebarContent>
      <SidebarGroup v-for="group in groups" :key="group.key">
        <SidebarGroupLabel v-if="group.label">{{ group.label }}</SidebarGroupLabel>
        <SidebarMenu>
          <SidebarMenuItem v-for="item in group.items" :key="item.to">
            <SidebarMenuButton as-child :is-active="isActive(item.to, item.exact)" :tooltip="item.label">
              <NuxtLink :to="item.to">
                <component :is="item.icon" />
                <span>{{ item.label }}</span>
              </NuxtLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarGroup>

      <SidebarGroup class="mt-auto">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton as-child size="sm" :is-active="isActive('/settings')" :tooltip="t('nav.settings')">
              <NuxtLink to="/settings">
                <SettingsIcon />
                <span>{{ t('nav.settings') }}</span>
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
