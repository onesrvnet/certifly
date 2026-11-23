<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { CheckIcon, ChevronsUpDownIcon, SearchIcon, XIcon } from '@lucide/vue'

import type { Person } from '~/types/api'

/**
 * Pick one person: a button that opens a searchable list. With `clearable` the choice can be
 * removed again. `exclude` hides people who are already taken, e.g. members of a group.
 */
const model = defineModel<Person | null>({ default: null })
const props = defineProps<{ id?: string; placeholder: string; clearable?: boolean; exclude?: string[]; disabled?: boolean }>()
const { t } = useI18n()
const rpc = useRpc()
const showError = useErrorToast()

const open = ref(false)
const search = ref('')
const query = refDebounced(search, 250)
const people = ref<Person[]>([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    const res = await rpc('users.list', { query: query.value.trim() || undefined, limit: 50 })
    // Admins get complete rows, operators short ones; both carry what a picker shows.
    people.value = res.data as unknown as Person[]
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

watch(open, (isOpen) => {
  if (!isOpen) return
  search.value = ''
  void load()
})
watch(query, () => {
  if (open.value) void load()
})

const shown = computed(() => people.value.filter((person) => !props.exclude?.includes(person.id)))

function pick(person: Person) {
  model.value = person
  open.value = false
}
</script>

<template>
  <div class="flex items-center gap-1">
    <Popover v-model:open="open">
      <PopoverTrigger as-child>
        <Button :id="id" type="button" variant="outline" role="combobox" :aria-expanded="open" :disabled="disabled" class="min-w-0 flex-1 justify-between font-normal">
          <span v-if="model" class="flex min-w-0 items-center gap-2">
            <UserAvatar :name="model.name" class="size-5" />
            <span class="truncate">{{ model.name }}</span>
            <span class="truncate text-xs text-muted-foreground">{{ model.email }}</span>
          </span>
          <span v-else class="truncate text-muted-foreground">{{ placeholder }}</span>
          <ChevronsUpDownIcon class="ml-2 size-4 shrink-0 text-muted-foreground" />
        </Button>
      </PopoverTrigger>
      <PopoverContent class="w-(--reka-popover-trigger-width) min-w-64 p-0" align="start">
        <div class="relative border-b">
          <SearchIcon class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <input v-model="search" type="search" class="h-9 w-full bg-transparent pr-2 pl-8 text-sm outline-none placeholder:text-muted-foreground" :placeholder="t('personPicker.search')" :aria-label="t('personPicker.search')" />
        </div>
        <ul class="max-h-64 overflow-y-auto p-1" role="listbox">
          <li v-for="person in shown" :key="person.id">
            <button
              type="button"
              role="option"
              :aria-selected="model?.id === person.id"
              class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
              @click="pick(person)"
            >
              <UserAvatar :name="person.name" class="size-6" />
              <span class="flex min-w-0 flex-1 flex-col">
                <span class="truncate">{{ person.name }}</span>
                <span class="truncate text-xs text-muted-foreground">{{ person.email }}</span>
              </span>
              <CheckIcon v-if="model?.id === person.id" class="size-4 shrink-0" />
            </button>
          </li>
          <li v-if="!shown.length && !loading" class="px-2 py-3 text-center text-sm text-muted-foreground">{{ t('personPicker.none') }}</li>
        </ul>
      </PopoverContent>
    </Popover>
    <Button v-if="clearable && model" type="button" variant="ghost" size="icon" class="shrink-0" :aria-label="t('personPicker.clear')" :title="t('personPicker.clear')" @click="model = null"><XIcon /></Button>
  </div>
</template>
