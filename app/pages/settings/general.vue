<script setup lang="ts">
import { toast } from 'vue-sonner'

/** Instance settings (admins). Kept minimal: more settings appear here as features need them. */
definePageMeta({ titleKey: 'settings.title', requires: ['instance', 'read_settings'] })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('settings.general.title') })


const { data: settings } = await useAsyncData('settings', async () => (await rpc('settings.list')).data, { default: () => ({}) as Record<string, unknown> })

const saved = computed(() => (typeof settings.value['instance.name'] === 'string' ? (settings.value['instance.name'] as string) : ''))
const name = ref(saved.value)
const canUpdate = computed(() => auth.can('instance', 'update_settings'))
const dirty = computed(() => name.value.trim() !== saved.value)

const save = useAction(async () => {
  settings.value = (await rpc('settings.update', { key: 'instance.name', value: name.value.trim() })).data
  toast.success(t('common.saved'))
})
</script>

<template>
  <SettingsSection :title="t('settings.general.title')" :description="t('settings.general.description')">
    <form class="flex max-w-md flex-col gap-6" @submit.prevent="save">
      <FieldGroup>
        <Field>
          <FieldLabel for="instance-name">{{ t('settings.general.name') }}</FieldLabel>
          <Input id="instance-name" v-model="name" maxlength="100" :placeholder="t('settings.general.namePlaceholder')" :disabled="!canUpdate" />
          <FieldDescription>{{ t('settings.general.nameHint') }}</FieldDescription>
        </Field>
      </FieldGroup>
      <div>
        <Button type="submit" :loading="save.busy" :disabled="!canUpdate || !dirty || !name.trim()">{{ t('common.save') }}</Button>
      </div>
    </form>
  </SettingsSection>
</template>
