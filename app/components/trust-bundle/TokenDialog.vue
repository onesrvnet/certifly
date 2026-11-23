<script setup lang="ts">
import { CopyIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

/**
 * A bundle's Traefik token, shown once after it was made. The parent keeps it only while the dialog
 * is open: closing sets it back to null.
 */
const token = defineModel<string | null>({ required: true })
const { t } = useI18n()

async function copy() {
  if (!token.value) return
  await navigator.clipboard.writeText(token.value)
  toast.success(t('common.copied'))
}
</script>

<template>
  <Dialog :open="!!token" @update:open="(open) => { if (!open) token = null }">
    <DialogContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ t('trustBundles.traefik.tokenTitle') }}</DialogTitle>
        <DialogDescription>{{ t('trustBundles.traefik.tokenWarning') }}</DialogDescription>
      </DialogHeader>
      <div class="flex gap-2">
        <Input :model-value="token ?? ''" readonly class="font-mono text-xs" :aria-label="t('trustBundles.traefik.tokenLabel')" @focus="($event.target as HTMLInputElement).select()" />
        <Button variant="outline" size="icon" class="shrink-0" :aria-label="t('trustBundles.traefik.copyToken')" @click="copy"><CopyIcon class="size-4" /></Button>
      </div>
      <DialogFooter>
        <Button @click="token = null">{{ t('common.done') }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
