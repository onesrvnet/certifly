<script setup lang="ts">
import { ChevronsUpDownIcon, LogOutIcon, MonitorIcon, MoonIcon, SettingsIcon, SunIcon, UserIcon } from '@lucide/vue'

import { useSidebar } from '~/components/ui/sidebar'

const { t } = useI18n()
const auth = useAuthStore()
const { isMobile } = useSidebar()
const { store: theme } = useTheme()

const themes = computed(() => [
  { value: 'light', label: t('userMenu.themeLight'), icon: SunIcon },
  { value: 'dark', label: t('userMenu.themeDark'), icon: MoonIcon },
  { value: 'auto', label: t('userMenu.themeSystem'), icon: MonitorIcon },
])

async function logout() {
  await auth.logout()
  await navigateTo('/login')
}
</script>

<template>
  <SidebarMenu v-if="auth.user">
    <SidebarMenuItem>
      <DropdownMenu>
        <DropdownMenuTrigger as-child>
          <SidebarMenuButton size="lg" class="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
            <UserAvatar :name="auth.user.name" class="size-8 rounded-lg" />
            <div class="grid flex-1 text-left text-sm leading-tight">
              <span class="truncate font-medium">{{ auth.user.name }}</span>
              <span class="truncate text-xs text-muted-foreground">{{ auth.user.email }}</span>
            </div>
            <ChevronsUpDownIcon class="ml-auto size-4" />
          </SidebarMenuButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          class="w-(--reka-dropdown-menu-trigger-width) min-w-56 rounded-lg"
          :side="isMobile ? 'bottom' : 'right'"
          align="end"
          :side-offset="4"
        >
          <DropdownMenuGroup>
            <DropdownMenuItem as-child>
              <NuxtLink to="/settings/profile"><UserIcon />{{ t('userMenu.profile') }}</NuxtLink>
            </DropdownMenuItem>
            <DropdownMenuItem as-child>
              <NuxtLink to="/settings"><SettingsIcon />{{ t('userMenu.settings') }}</NuxtLink>
            </DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>
                <SunIcon class="text-muted-foreground" />{{ t('userMenu.theme') }}
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuRadioGroup v-model="theme">
                  <DropdownMenuRadioItem v-for="option in themes" :key="option.value" :value="option.value">
                    <component :is="option.icon" class="size-4" />{{ option.label }}
                  </DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem @select="logout">
            <LogOutIcon />{{ t('userMenu.logout') }}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </SidebarMenuItem>
  </SidebarMenu>
</template>
