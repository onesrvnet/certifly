<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { SearchIcon } from '@lucide/vue'

/**
 * A dialog with a search box and a list to choose one entry from, loaded by `load` as the
 * search changes. Used by filters that pick a person or a host.
 */
export interface SearchListItem {
  id: string
  label: string
  detail?: string
}

const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ title: string; placeholder: string; load: (query: string) => Promise<SearchListItem[]> }>()
const emit = defineEmits<{ pick: [item: SearchListItem] }>()
const { t } = useI18n()
const showError = useErrorToast()

const search = ref('')
const query = refDebounced(search, 250)
const items = ref<SearchListItem[]>([])
const loading = ref(false)

async function run() {
  loading.value = true
  try {
    items.value = await props.load(query.value.trim())
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

watch(open, (isOpen) => {
  if (!isOpen) return
  search.value = ''
  void run()
})
watch(query, () => {
  if (open.value) void run()
})

function pick(item: SearchListItem) {
  emit('pick', item)
  open.value = false
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ title }}</DialogTitle>
        <DialogDescription class="sr-only">{{ title }}</DialogDescription>
      </DialogHeader>
      <div class="relative">
        <SearchIcon class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="search" type="search" class="pl-8" :placeholder="placeholder" :aria-label="placeholder" autocomplete="off" spellcheck="false" />
      </div>
      <ul class="max-h-72 overflow-y-auto rounded-md border" role="listbox">
        <li v-for="item in items" :key="item.id" class="border-b last:border-b-0">
          <button type="button" role="option" class="flex w-full flex-col px-3 py-2 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none" @click="pick(item)">
            <span class="truncate">{{ item.label }}</span>
            <span v-if="item.detail" class="truncate text-xs text-muted-foreground">{{ item.detail }}</span>
          </button>
        </li>
        <li v-if="!items.length && !loading" class="px-3 py-4 text-center text-sm text-muted-foreground">{{ t('searchList.none') }}</li>
      </ul>
    </DialogContent>
  </Dialog>
</template>
