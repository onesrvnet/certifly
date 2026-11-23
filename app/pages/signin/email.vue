<script setup lang="ts">
// Sign-in links require an explicit click so mail scanners that prefetch links don't consume the token.
definePageMeta({ layout: 'auth' })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const route = useRoute()
const errorMessage = useErrorMessage()

useHead({ title: () => t('auth.confirmTitle') })

const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const pending = ref(false)
const error = ref(token.value ? '' : t('auth.invalidLink'))

async function confirm() {
  pending.value = true
  error.value = ''
  try {
    await rpc('sign_in_codes.verify', { token: token.value })
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
      <CardTitle class="text-xl">{{ t('auth.confirmTitle') }}</CardTitle>
      <CardDescription>{{ t('auth.confirmDescription') }}</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <Alert v-if="error" variant="destructive">
        <AlertDescription>{{ error }}</AlertDescription>
      </Alert>
      <Button v-if="token" :loading="pending" @click="confirm">{{ t('auth.confirmButton') }}</Button>
      <Button variant="link" as-child>
        <NuxtLink to="/login">{{ t('auth.backToLogin') }}</NuxtLink>
      </Button>
    </CardContent>
  </Card>
</template>
