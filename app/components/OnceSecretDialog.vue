<script setup lang="ts">
/**
 * Credentials shown once right after they were made (an EAB key, an EST password): each value with
 * a copy button, and optionally a ready-to-run example. Closing drops them: the parent sets the
 * model back to null and keeps nothing.
 */
export interface OnceSecret {
  title: string
  fields: { label: string; value: string }[]
  example?: { label: string; value: string }
  /** Short labelled facts shown as chips under the values, e.g. how long a token is valid. */
  facts?: { label: string; value: string }[]
}

const secret = defineModel<OnceSecret | null>({ required: true })
const { t } = useI18n()
</script>

<template>
  <Dialog :open="!!secret" @update:open="(open) => { if (!open) secret = null }">
    <DialogContent class="sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>{{ secret?.title }}</DialogTitle>
        <DialogDescription>{{ t('common.shownOnce') }}</DialogDescription>
      </DialogHeader>
      <div v-if="secret" class="flex min-w-0 flex-col gap-3">
        <CaCopyField v-for="field in secret.fields" :key="field.label" :label="field.label" :value="field.value" />
        <div v-if="secret.example" class="flex min-w-0 flex-col gap-1">
          <CaCopyField :label="secret.example.label" :value="secret.example.value" />
        </div>
        <div v-if="secret.facts?.length" class="flex flex-wrap gap-2">
          <MetaChip v-for="fact in secret.facts" :key="fact.label" :label="fact.label">{{ fact.value }}</MetaChip>
        </div>
      </div>
      <DialogFooter>
        <Button @click="secret = null">{{ t('common.done') }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
