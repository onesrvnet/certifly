<script setup lang="ts">
import { CopyIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

/** A labelled, read-only value (a URL, a fingerprint) with a copy button. */
const props = defineProps<{ label: string; value: string }>()
const { t } = useI18n()

async function copy() {
  await navigator.clipboard.writeText(props.value)
  toast.success(t('common.copied'))
}
</script>

<template>
  <div class="flex min-w-0 flex-col gap-1">
    <span class="text-xs text-muted-foreground">{{ label }}</span>
    <div class="flex min-w-0 items-center gap-2">
      <code class="min-w-0 flex-1 truncate rounded-md border bg-muted/40 px-2 py-1.5 font-mono text-xs" :title="value">{{ value }}</code>
      <Button variant="outline" size="icon-sm" class="shrink-0" :aria-label="t('cas.detail.copyUrl', { label })" :title="t('cas.detail.copyUrl', { label })" @click="copy">
        <CopyIcon />
      </Button>
    </div>
  </div>
</template>
