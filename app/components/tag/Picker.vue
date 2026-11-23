<script setup lang="ts">
import { CheckIcon, SearchIcon } from '@lucide/vue'

/**
 * A searchable checklist of the managed tags in a popover. The trigger goes in the default slot;
 * with `apply`, changes are collected and confirmed with a button (editing a certificate),
 * otherwise each click updates the model at once (filters).
 */
const props = defineProps<{ tags: TagRef[]; apply?: string; busy?: boolean; align?: 'start' | 'end' }>()
const model = defineModel<string[]>({ required: true })
const emit = defineEmits<{ apply: [ids: string[]] }>()
const { t } = useI18n()

const open = ref(false)
const search = ref('')
const draft = ref<string[]>([])

watch(open, (isOpen) => {
  if (!isOpen) return
  search.value = ''
  draft.value = [...model.value]
})

const selected = computed(() => (props.apply ? draft.value : model.value))
const shown = computed(() => {
  const q = search.value.trim().toLowerCase()
  return q ? props.tags.filter((tag) => tag.name.toLowerCase().includes(q)) : props.tags
})

function toggle(id: string) {
  const next = selected.value.includes(id) ? selected.value.filter((x) => x !== id) : [...selected.value, id]
  if (props.apply) draft.value = next
  else model.value = next
}

function confirm() {
  emit('apply', draft.value)
  open.value = false
}
</script>

<template>
  <Popover v-model:open="open">
    <PopoverTrigger as-child><slot /></PopoverTrigger>
    <PopoverContent class="w-64 p-0" :align="align ?? 'start'">
      <div class="relative border-b">
        <SearchIcon class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <input v-model="search" type="search" class="h-9 w-full bg-transparent pr-2 pl-8 text-sm outline-none placeholder:text-muted-foreground" :placeholder="t('tags.search')" :aria-label="t('tags.search')" />
      </div>
      <ul class="max-h-64 overflow-y-auto p-1" role="listbox" aria-multiselectable="true">
        <li v-for="tag in shown" :key="tag.id">
          <button
            type="button"
            role="option"
            :aria-selected="selected.includes(tag.id)"
            class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
            @click="toggle(tag.id)"
          >
            <span class="flex size-4 shrink-0 items-center justify-center rounded-sm border" :class="selected.includes(tag.id) && 'border-primary bg-primary text-primary-foreground'">
              <CheckIcon v-if="selected.includes(tag.id)" class="size-3" />
            </span>
            <TagDot :color="tag.color" />
            <span class="truncate">{{ tag.name }}</span>
          </button>
        </li>
        <li v-if="!shown.length" class="px-2 py-3 text-center text-sm text-muted-foreground">{{ t('tags.noMatch') }}</li>
      </ul>
      <div v-if="apply" class="flex justify-end border-t p-2">
        <Button size="sm" :loading="busy" @click="confirm">{{ apply }}</Button>
      </div>
    </PopoverContent>
  </Popover>
</template>
