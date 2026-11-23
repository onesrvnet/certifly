<script setup lang="ts">
import { CopyIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

/** A shell command to copy, e.g. the `openssl verify` line for the downloaded files. */
const props = defineProps<{ command: string }>()
const { t } = useI18n()

async function copy() {
  await navigator.clipboard.writeText(props.command)
  toast.success(t('common.copied'))
}
</script>

<template>
  <div class="flex items-start gap-2">
    <pre class="min-w-0 flex-1 overflow-x-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs leading-relaxed"><code>{{ command }}</code></pre>
    <Button variant="outline" size="icon-sm" class="shrink-0" :aria-label="t('common.copy')" :title="t('common.copy')" @click="copy"><CopyIcon /></Button>
  </div>
</template>
