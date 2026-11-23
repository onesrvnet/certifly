<script setup lang="ts">
import { CopyIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

/** A labelled block of text (a config snippet, an authorized_keys line) with a copy button. */
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
    <div class="flex min-w-0 items-start gap-2">
      <pre class="min-w-0 flex-1 overflow-x-auto rounded-md border bg-muted/40 px-2 py-1.5 font-mono text-xs break-all whitespace-pre-wrap">{{ value }}</pre>
      <Button variant="outline" size="icon-sm" class="shrink-0" :aria-label="t('cas.detail.copyUrl', { label })" :title="t('cas.detail.copyUrl', { label })" @click="copy"><CopyIcon /></Button>
    </div>
  </div>
</template>
