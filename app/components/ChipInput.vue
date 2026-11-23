<script setup lang="ts">
import { XIcon } from '@lucide/vue'

/**
 * A list of short values as removable chips with a text box behind them. Enter, comma or leaving
 * the box adds the typed value; Backspace in an empty box removes the last chip. `check` returns
 * a message for a value that cannot be added.
 */
const model = defineModel<string[]>({ required: true })
const props = defineProps<{
  id: string
  label?: string
  info?: string
  placeholder?: string
  error?: string
  disabled?: boolean
  mono?: boolean
  lowercase?: boolean
  check?: (value: string) => string | null
  /** Chips the server found fault with. */
  problems?: string[]
}>()
const { t } = useI18n()

const draft = ref('')
const local = ref('')

function add() {
  let value = draft.value.trim().replace(/,$/, '').trim()
  if (!value) return
  if (props.lowercase) value = value.toLowerCase()
  const problem = props.check?.(value) ?? null
  if (problem) {
    local.value = problem
    return
  }
  if (!model.value.includes(value)) model.value = [...model.value, value]
  draft.value = ''
  local.value = ''
}

function remove(value: string) {
  model.value = model.value.filter((v) => v !== value)
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Enter' || event.key === ',') {
    event.preventDefault()
    add()
  } else if (event.key === 'Backspace' && !draft.value && model.value.length && !props.disabled) {
    model.value = model.value.slice(0, -1)
  }
}
</script>

<template>
  <Field :data-invalid="!!(local || error) || undefined">
    <div v-if="label" class="flex items-center gap-1.5">
      <FieldLabel :for="id">{{ label }}</FieldLabel>
      <InfoTip v-if="info" :text="info" />
    </div>
    <div
      class="flex min-h-9 w-full flex-wrap items-center gap-1.5 rounded-md border border-input bg-transparent px-2 py-1 shadow-xs transition-[color,box-shadow] focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50 dark:bg-input/30"
      :class="[(local || error) && 'border-destructive', disabled && 'pointer-events-none opacity-50']"
    >
      <Badge v-for="value in model" :key="value" variant="secondary" class="gap-1 py-0.5 pr-0.5 pl-2 text-xs" :class="[mono && 'font-mono', problems?.includes(value) && 'border-danger/40 bg-danger-soft text-danger']">
        {{ value }}
        <button type="button" class="rounded-full p-0.5 hover:bg-background/60" :aria-label="t('chipInput.remove', { value })" @click="remove(value)">
          <XIcon class="size-3" />
        </button>
      </Badge>
      <input
        :id="id"
        v-model="draft"
        :placeholder="model.length ? '' : placeholder"
        :disabled="disabled"
        autocomplete="off"
        spellcheck="false"
        class="min-w-24 flex-1 bg-transparent py-0.5 text-sm outline-none placeholder:text-muted-foreground"
        :class="mono && 'font-mono'"
        @keydown="onKeydown"
        @blur="add"
        @input="local = ''"
      />
    </div>
    <FieldError v-if="local || error">{{ local || error }}</FieldError>
  </Field>
</template>
