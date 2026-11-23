<script setup lang="ts">
import { PlusIcon, XIcon } from '@lucide/vue'

import type { SanInput, SanType } from '~/types/api'

/** Edits the SANs of a request: one row per name, of the types the template allows. */
const model = defineModel<SanInput[]>({ required: true })
const props = defineProps<{ types: SanType[]; idPrefix: string; error?: string; invalid?: string[]; info?: string }>()
const { t } = useI18n()

function add() {
  model.value = [...model.value, { type: props.types[0] ?? 'dns', value: '' }]
}
function remove(index: number) {
  model.value = model.value.filter((_, i) => i !== index)
}
function update(index: number, patch: Partial<SanInput>) {
  model.value = model.value.map((san, i) => (i === index ? { ...san, ...patch } : san))
}
</script>

<template>
  <Field :data-invalid="!!error || undefined">
    <div class="flex items-center gap-1.5">
      <FieldLabel :for="`${idPrefix}-san-0`">{{ t('certificates.issue.sans') }}</FieldLabel>
      <InfoTip v-if="info" :text="info" />
    </div>
    <ul v-if="model.length" class="flex flex-col gap-2">
      <li v-for="(san, index) in model" :key="index" class="flex gap-2">
        <Select :model-value="san.type" @update:model-value="update(index, { type: $event as SanType })">
          <SelectTrigger class="w-28 shrink-0" :aria-label="t('certificates.issue.sanType')"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem v-for="type in types" :key="type" :value="type">{{ t(`certificates.sanTypes.${type}`) }}</SelectItem>
          </SelectContent>
        </Select>
        <Input
          :id="`${idPrefix}-san-${index}`"
          :model-value="san.value"
          :placeholder="t(`certificates.sanPlaceholders.${san.type}`)"
          :aria-invalid="invalid?.includes(`${san.type}:${san.value.trim().toLowerCase()}`) || undefined"
          autocomplete="off"
          spellcheck="false"
          class="min-w-0 font-mono text-sm"
          @update:model-value="update(index, { value: String($event) })"
        />
        <Button type="button" variant="outline" size="icon" class="shrink-0" :aria-label="t('certificates.issue.removeSan')" :title="t('certificates.issue.removeSan')" @click="remove(index)"><XIcon /></Button>
      </li>
    </ul>
    <Button type="button" variant="outline" size="sm" class="self-start" :disabled="!types.length" @click="add"><PlusIcon />{{ t('certificates.issue.addSan') }}</Button>
    <FieldError v-if="error">{{ error }}</FieldError>
  </Field>
</template>
