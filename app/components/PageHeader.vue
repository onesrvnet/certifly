<script setup lang="ts">
import { useSidebar } from '~/components/ui/sidebar'

const { t } = useI18n()
// The sidebar has its own toggle; the header only needs one to bring a hidden sidebar back.
// On small screens the sidebar is a sheet, so the trigger always shows there. That's done
// with CSS: the server can't know the screen size, and a JS check would pop in after load.
const { state } = useSidebar()
const collapsed = computed(() => state.value === 'collapsed')
</script>

<template>
  <header class="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
    <div class="flex shrink-0 items-center gap-2" :class="!collapsed && 'md:hidden'">
      <SidebarTrigger :aria-label="t('nav.toggleSidebar')" />
      <Separator orientation="vertical" class="mr-1 data-[orientation=vertical]:h-4" />
    </div>
    <div class="flex min-w-0 flex-1 items-center gap-2 text-sm">
      <slot />
    </div>
    <div v-if="$slots.actions" class="flex shrink-0 items-center gap-1">
      <slot name="actions" />
    </div>
  </header>
</template>
