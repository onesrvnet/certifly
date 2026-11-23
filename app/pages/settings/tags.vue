<script setup lang="ts">
import { PencilIcon, PlusIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

/** The managed tag list (admins): name and colour, and how often each tag is used. */
definePageMeta({ titleKey: 'settings.title', requires: ['instance', 'manage_tags'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('tags.title') })

const { data: tags, refresh } = await useAsyncData(
  'tags',
  async () => {
    const res = await rpc('tags.list')
    auth.remember(res.data)
    return res.data
  },
  { default: () => [] },
)

// One dialog for create and edit.
const dialogOpen = ref(false)
const editing = ref<{ id: string } | null>(null)
const name = ref('')
const color = ref<TagColor>('blue')

function openCreate() {
  editing.value = null
  name.value = ''
  color.value = 'blue'
  dialogOpen.value = true
}

function openEdit(tag: { id: string; name: string; color: string }) {
  editing.value = { id: tag.id }
  name.value = tag.name
  color.value = (TAG_COLORS as readonly string[]).includes(tag.color) ? (tag.color as TagColor) : 'gray'
  dialogOpen.value = true
}

const save = useAction(async () => {
  const body = { name: name.value.trim(), color: color.value }
  if (editing.value) await rpc('tags.update', { id: editing.value.id, ...body })
  else await rpc('tags.create', body)
  toast.success(t(editing.value ? 'tags.updated' : 'tags.created', { name: body.name }))
  dialogOpen.value = false
  await refresh()
})

const deleting = ref<{ id: string; name: string; certificate_count: number } | null>(null)
const remove = useAction(async () => {
  if (!deleting.value) return
  await rpc('tags.delete', { id: deleting.value.id })
  toast.success(t('tags.deleted', { name: deleting.value.name }))
  deleting.value = null
  await refresh()
})
</script>

<template>
  <SettingsSection :title="t('tags.title')" :description="t('tags.description')">
    <div class="flex justify-end">
      <Button v-if="auth.can('instance', 'manage_tags')" @click="openCreate"><PlusIcon />{{ t('tags.new') }}</Button>
    </div>

    <ul v-if="tags.length" class="divide-y rounded-md border">
      <li v-for="tag in tags" :key="tag.id" class="flex items-center gap-3 px-4 py-3 text-sm">
        <TagChip :name="tag.name" :color="tag.color" />
        <span class="ml-auto flex flex-wrap justify-end gap-2">
          <MetaChip :label="t('tags.certificates')">{{ tag.certificate_count }}</MetaChip>
          <MetaChip :label="t('tags.templates')">{{ tag.template_count }}</MetaChip>
        </span>
        <span class="flex gap-1">
          <Button v-if="auth.can(tag.id, 'update')" variant="ghost" size="icon" class="size-8" :aria-label="t('tags.edit')" :title="t('tags.edit')" @click="openEdit(tag)"><PencilIcon class="size-4" /></Button>
          <Button v-if="auth.can(tag.id, 'delete')" variant="ghost" size="icon" class="size-8 text-destructive" :aria-label="t('tags.delete')" :title="t('tags.delete')" @click="deleting = tag"><Trash2Icon class="size-4" /></Button>
        </span>
      </li>
    </ul>
    <div v-else class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">{{ t('tags.empty') }}</div>

    <Dialog v-model:open="dialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ editing ? t('tags.edit') : t('tags.new') }}</DialogTitle>
        </DialogHeader>
        <form class="flex flex-col gap-5" @submit.prevent="save">
          <Field>
            <FieldLabel for="tag-name">{{ t('tags.name') }}</FieldLabel>
            <Input id="tag-name" v-model="name" maxlength="40" required autocomplete="off" :placeholder="t('tags.namePlaceholder')" />
          </Field>
          <Field>
            <FieldLabel>{{ t('tags.color') }}</FieldLabel>
            <div class="flex flex-wrap gap-2" role="radiogroup" :aria-label="t('tags.color')">
              <button
                v-for="option in TAG_COLORS"
                :key="option"
                type="button"
                role="radio"
                :aria-checked="color === option"
                :aria-label="t(`tags.colors.${option}`)"
                :title="t(`tags.colors.${option}`)"
                class="flex size-8 items-center justify-center rounded-full border transition-shadow focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                :class="color === option && 'ring-2 ring-ring ring-offset-2 ring-offset-background'"
                :style="tagStyle(option)"
                @click="color = option"
              >
                <TagDot :color="option" />
              </button>
            </div>
          </Field>
          <div class="flex items-center gap-2">
            <span class="text-xs text-muted-foreground">{{ t('tags.preview') }}</span>
            <TagChip :name="name.trim() || t('tags.namePlaceholder')" :color="color" />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" @click="dialogOpen = false">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="save.busy" :disabled="!name.trim()">{{ editing ? t('common.save') : t('tags.create') }}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!deleting" @update:open="(open) => !open && (deleting = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('tags.deleteTitle', { name: deleting?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('tags.deleteText', { count: deleting?.certificate_count ?? 0 }) }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleting = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove">{{ t('tags.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </SettingsSection>
</template>
