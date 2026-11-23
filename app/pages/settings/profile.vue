<script setup lang="ts">
import { toast } from 'vue-sonner'

definePageMeta({ titleKey: 'settings.title' })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

useHead({ title: () => t('settings.profile.title') })

const name = ref(auth.user?.name ?? '')
const dirty = computed(() => name.value.trim() !== auth.user?.name)

const save = useAction(async () => {
  const res = await rpc('users.update', { name: name.value.trim() })
  auth.user = { ...auth.user!, ...res.data }
  auth.remember(res.data)
  toast.success(t('common.saved'))
})
</script>

<template>
  <SettingsSection :title="t('settings.profile.title')" :description="t('settings.profile.description')">
    <form class="flex max-w-md flex-col gap-6" @submit.prevent="save">
      <FieldGroup>
        <Field>
          <FieldLabel for="name">{{ t('settings.profile.name') }}</FieldLabel>
          <Input id="name" v-model="name" maxlength="100" required :disabled="!auth.can(auth.user?.id, 'update')" />
        </Field>
        <Field>
          <FieldLabel for="email">{{ t('settings.profile.email') }}</FieldLabel>
          <Input id="email" :model-value="auth.user?.email ?? ''" disabled />
          <FieldDescription>{{ t('settings.profile.emailHint') }}</FieldDescription>
        </Field>
        <Field>
          <FieldLabel for="role">{{ t('settings.profile.role') }}</FieldLabel>
          <Input id="role" :model-value="t(`roles.${auth.user?.role ?? 'viewer'}`)" disabled />
          <FieldDescription>{{ t(auth.can(auth.user?.id, 'change_role') ? 'settings.profile.roleHintAdmin' : 'settings.profile.roleHint') }}</FieldDescription>
        </Field>
      </FieldGroup>
      <div>
        <Button type="submit" :loading="save.busy" :disabled="!dirty || !name.trim()">{{ t('common.save') }}</Button>
      </div>
    </form>
  </SettingsSection>
</template>
