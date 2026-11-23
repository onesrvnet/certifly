<script setup lang="ts">
import { InfoIcon } from '@lucide/vue'

/**
 * Help for one field or card behind a small info icon: the text shows on hover and on keyboard
 * focus, and a tap opens and closes it on touch screens, which have no hover.
 */
const props = defineProps<{ text: string; label?: string }>()
const { t } = useI18n()

const open = ref(false)
let pointerType = ''
let wasOpen = false

function onPointerDown(event: PointerEvent) {
  pointerType = event.pointerType
  wasOpen = open.value
}

function onClick() {
  // A tap toggles; a mouse click or Enter/Space only ever opens, since hover or focus already did.
  open.value = pointerType === 'touch' || pointerType === 'pen' ? !wasOpen : true
  pointerType = ''
}
</script>

<template>
  <TooltipProvider>
    <Tooltip v-model:open="open" disable-closing-trigger>
      <TooltipTrigger as-child>
        <button
          type="button"
          class="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50"
          :aria-label="props.label ?? t('common.moreInfo')"
          @pointerdown="onPointerDown"
          @click="onClick"
        >
          <InfoIcon class="size-3.5" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent class="max-w-64">{{ props.text }}</TooltipContent>
    </Tooltip>
  </TooltipProvider>
</template>
