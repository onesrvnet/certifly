<script setup lang="ts">
import { TriangleAlertIcon } from '@lucide/vue'

import type { RpcOutput } from '~/types/api'

// Like sign-in links, invite links need an explicit click so mail scanners don't consume them.
definePageMeta({ layout: 'auth' })

const { t, d } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const route = useRoute()
const errorMessage = useErrorMessage()

useHead({ title: () => t('invite.title') })

type Preview = RpcOutput<'invite_acceptances.get'>['data']

const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const name = ref('')
const pending = ref(false)
const error = ref(token.value ? '' : t('invite.invalidLink'))

// Show what the link offers before anyone clicks: the address, the role and who sent it.
const { data: preview, status } = await useAsyncData<Preview | null>(
  'invite-preview',
  async () => {
    if (!token.value) return null
    try {
      return (await rpc('invite_acceptances.get', { token: token.value })).data
    } catch (err) {
      error.value = errorMessage(err)
      return null
    }
  },
  { default: () => null },
)

/** Someone else is signed in in this browser; accepting replaces their session, so say so first. */
const signedInAsOther = computed(() => !!auth.user && !!preview.value && auth.user.email !== preview.value.email)

async function accept() {
  pending.value = true
  error.value = ''
  try {
    // End the other account's session properly instead of leaving it behind.
    if (auth.user) await rpc('sessions.delete', {})
    await rpc('invite_acceptances.create', { token: token.value, ...(name.value.trim() ? { name: name.value.trim() } : {}) })
    await auth.load()
    await navigateTo('/')
  } catch (err) {
    error.value = errorMessage(err)
  } finally {
    pending.value = false
  }
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">{{ t('invite.title') }}</CardTitle>
      <CardDescription v-if="preview">
        {{
          preview.inviter_name
            ? t('invite.details', { inviter: preview.inviter_name, email: preview.email, role: t(`roles.${preview.role}`) })
            : t('invite.detailsNoInviter', { email: preview.email, role: t(`roles.${preview.role}`) })
        }}
      </CardDescription>
      <CardDescription v-else-if="status === 'pending'">{{ t('invite.detailsLoading') }}</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <Alert v-if="error" variant="destructive">
        <AlertDescription>{{ error }}</AlertDescription>
      </Alert>
      <template v-if="preview">
        <Alert v-if="signedInAsOther">
          <TriangleAlertIcon />
          <AlertTitle>{{ t('invite.signedInAsOther', { email: auth.user?.email ?? '' }) }}</AlertTitle>
          <AlertDescription>{{ t('invite.signedInAsOtherHint') }}</AlertDescription>
        </Alert>
        <form class="flex flex-col gap-4" @submit.prevent="accept">
          <Field>
            <FieldLabel for="name">{{ t('invite.name') }}</FieldLabel>
            <Input id="name" v-model="name" maxlength="100" autocomplete="name" :placeholder="t('invite.namePlaceholder')" />
            <FieldDescription>{{ t('invite.nameHint') }}</FieldDescription>
          </Field>
          <Button type="submit" :loading="pending">{{ signedInAsOther ? t('invite.acceptAndSwitch') : t('invite.accept') }}</Button>
          <p class="text-center text-xs text-muted-foreground">{{ t('invite.expires', { date: d(new Date(preview.expires_at), { dateStyle: 'medium' }) }) }}</p>
        </form>
      </template>
      <Button variant="link" as-child>
        <NuxtLink to="/login">{{ t('auth.backToLogin') }}</NuxtLink>
      </Button>
    </CardContent>
  </Card>
</template>
