<script setup lang="ts">
import { PlusIcon, XIcon } from '@lucide/vue'

/**
 * Edits a template's matching rules: domain patterns (`api.example.com`, `*.example.com`,
 * `**.example.com`) or CIDRs. Values are checked loosely here; the server decides, and its
 * problems with single rules are marked on their chips.
 */
const model = defineModel<string[]>({ required: true })
const props = defineProps<{ id: string; label: string; kind: 'pattern' | 'cidr'; placeholder?: string; info?: string; error?: string; problems?: string[]; disabled?: boolean }>()
const { t } = useI18n()

const draft = ref('')
const local = ref('')

const LABEL = '(?!-)[a-z0-9-]{1,63}(?<!-)'
const PATTERN = new RegExp(`^(\\*\\*?\\.)?${LABEL}(\\.${LABEL})+$|^${LABEL}$`)
const CIDR = /^(\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|[0-9a-f:]+(\/\d{1,3})?)$/i

function add() {
  const value = draft.value.trim().toLowerCase().replace(/\.$/, '')
  if (!value) return
  const valid = props.kind === 'pattern' ? PATTERN.test(value) : CIDR.test(value)
  if (!valid) {
    local.value = props.kind === 'pattern' ? t('templates.form.invalidPattern') : t('templates.form.invalidCidr')
    return
  }
  if (!model.value.includes(value)) model.value = [...model.value, value]
  draft.value = ''
  local.value = ''
}

function remove(value: string) {
  model.value = model.value.filter((v) => v !== value)
}
</script>

<template>
  <Field :data-invalid="!!(local || error) || undefined">
    <div class="flex items-center gap-1.5">
      <FieldLabel :for="id">{{ label }}</FieldLabel>
      <InfoTip v-if="info" :text="info" />
    </div>
    <div class="flex gap-2">
      <Input :id="id" v-model="draft" :placeholder="placeholder" :disabled="disabled" autocomplete="off" spellcheck="false" class="font-mono text-sm" @keydown.enter.prevent="add" @input="local = ''" />
      <Button type="button" variant="outline" size="icon" class="shrink-0" :disabled="disabled" :aria-label="t('common.add')" :title="t('common.add')" @click="add"><PlusIcon /></Button>
    </div>
    <FieldError v-if="local || error">{{ local || error }}</FieldError>
    <ul v-if="model.length" class="flex flex-wrap gap-1.5">
      <li v-for="value in model" :key="value">
        <Badge variant="secondary" class="gap-1 py-0.5 pr-0.5 pl-2 font-mono text-xs" :class="problems?.includes(value) && 'border-danger/40 bg-danger-soft text-danger'">
          {{ value }}
          <button v-if="!disabled" type="button" class="rounded-full p-0.5 hover:bg-background/60" :aria-label="t('templates.form.removeRule', { value })" @click="remove(value)">
            <XIcon class="size-3" />
          </button>
        </Badge>
      </li>
    </ul>
  </Field>
</template>
