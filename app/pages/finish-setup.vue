<script setup lang="ts">
import { FingerprintIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

/**
 * Shown right after setting up an instance that cannot send mail: the admin the setup token
 * created adds a passkey, so they can sign in again later. They may skip it; until they have
 * one, running setup again with the token gets them back into this account.
 */
definePageMeta({ layout: 'auth' })

const { t } = useI18n()
const auth = useAuthStore()
const errorMessage = useErrorMessage()
const passkeys = usePasskeys()

useHead({ title: () => t('finishSetup.title') })

const pending = ref(false)
const formError = ref('')

async function add() {
  formError.value = ''
  pending.value = true
  try {
    await passkeys.register(passkeys.defaultName())
    toast.success(t('passkeys.added'))
    await auth.load()
    await navigateTo('/', { replace: true })
  } catch (error) {
    if (isPasskeyCancel(error)) return
    // Nobody can confirm it is them again here: no mail and no passkey yet. Running setup
    // again with the token gives a fresh session.
    formError.value = isReauthRequired(error) ? t('finishSetup.stale') : errorMessage(error)
  } finally {
    pending.value = false
  }
}

async function later() {
  await navigateTo('/', { replace: true })
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">{{ t('finishSetup.title') }}</CardTitle>
      <CardDescription>{{ t('finishSetup.description') }}</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <Alert>
        <FingerprintIcon />
        <AlertTitle>{{ t('finishSetup.whyTitle') }}</AlertTitle>
        <AlertDescription>{{ t('finishSetup.why') }}</AlertDescription>
      </Alert>
      <p v-if="!passkeys.supported.value" class="text-sm text-destructive" role="alert">{{ t('passkeys.unsupported') }}</p>
      <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
      <Button :loading="pending" :disabled="!passkeys.supported.value" @click="add">
        <FingerprintIcon />{{ t('passkeys.add') }}
      </Button>
      <Button variant="ghost" size="sm" :disabled="pending" @click="later">{{ t('finishSetup.later') }}</Button>
    </CardContent>
  </Card>
</template>
