<script setup lang="ts">
import { PlusIcon, XIcon } from '@lucide/vue'

/**
 * Edits one list of name constraints (DNS suffixes or IP ranges): type a value, add it with Enter
 * or the button, remove it from its chip. Values are checked loosely here; the server decides.
 */
const model = defineModel<string[]>({ required: true })
const props = defineProps<{ id: string; label: string; kind: 'dns' | 'ip'; placeholder?: string; info?: string }>()
const { t } = useI18n()

const draft = ref('')
const error = ref('')

const DNS = /^\.?(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/
const CIDR = /^(\d{1,3}(\.\d{1,3}){3}\/\d{1,2}|[0-9a-f:]+\/\d{1,3})$/i

function add() {
  const value = draft.value.trim().toLowerCase().replace(/\.$/, '')
  if (!value) return
  const valid = props.kind === 'dns' ? DNS.test(value) : CIDR.test(value)
  if (!valid) {
    error.value = props.kind === 'dns' ? t('cas.nc.invalidDns') : t('cas.nc.invalidIp')
    return
  }
  if (!model.value.includes(value)) model.value = [...model.value, value]
  draft.value = ''
  error.value = ''
}

function remove(value: string) {
  model.value = model.value.filter((v) => v !== value)
}
</script>

<template>
  <Field :data-invalid="!!error || undefined">
    <div class="flex items-center gap-1.5">
      <FieldLabel :for="id">{{ label }}</FieldLabel>
      <InfoTip v-if="info" :text="info" />
    </div>
    <div class="flex gap-2">
      <Input :id="id" v-model="draft" :placeholder="placeholder" autocomplete="off" spellcheck="false" class="font-mono text-sm" @keydown.enter.prevent="add" @input="error = ''" />
      <Button type="button" variant="outline" size="icon" class="shrink-0" :aria-label="t('common.add')" :title="t('common.add')" @click="add"><PlusIcon /></Button>
    </div>
    <FieldError v-if="error">{{ error }}</FieldError>
    <ul v-if="model.length" class="flex flex-wrap gap-1.5">
      <li v-for="value in model" :key="value">
        <Badge variant="secondary" class="gap-1 py-0.5 pr-0.5 pl-2 font-mono text-xs">
          {{ value }}
          <button type="button" class="rounded-full p-0.5 hover:bg-background/60" :aria-label="t('cas.nc.remove', { value })" @click="remove(value)">
            <XIcon class="size-3" />
          </button>
        </Badge>
      </li>
    </ul>
  </Field>
</template>
