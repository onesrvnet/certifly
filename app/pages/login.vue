<script setup lang="ts">
import { FingerprintIcon } from '@lucide/vue'

definePageMeta({ layout: 'auth' })

const { t, te } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const route = useRoute()
const errorMessage = useErrorMessage()

const { data: config } = await useAsyncData('auth-config', async () => (await rpc('auth_config.get')).data)

/** How the instance gets its first admin; null once it has one. */
const setupMethod = computed(() => config.value?.setup_method ?? null)
const needsSetup = computed(() => setupMethod.value !== null)
/** No mail, but a setup token: its holder creates the admin with a form, without any email. */
const tokenSetup = computed(() => setupMethod.value === 'token')
const setupTokenRequired = computed(() => config.value?.setup_token_required ?? false)
const oidc = computed(() => (config.value?.oidc.enabled ? config.value.oidc : null))
/** False when the instance cannot send mail: then only passkeys and the identity provider sign in. */
const emailEnabled = computed(() => config.value?.email_enabled ?? true)

useHead({ title: () => (needsSetup.value ? t('auth.setupTitle') : t('auth.signInTitle')) })

const description = computed(() => {
  if (tokenSetup.value) return t('auth.tokenSetupDescription')
  if (setupMethod.value === 'unavailable') return t('auth.setupUnavailableDescription')
  if (needsSetup.value) return t('auth.setupDescription')
  return emailEnabled.value ? t('auth.signInDescription') : t('auth.signInDescriptionNoEmail')
})

const step = ref<'email' | 'code'>('email')
const email = ref('')
const setupToken = ref(typeof route.query.setup_token === 'string' ? route.query.setup_token : '')
// Keep the token out of the address bar and browser history once it is in the form.
onMounted(() => {
  if (route.query.setup_token === undefined) return
  const { setup_token: _, ...rest } = route.query
  void navigateTo({ query: rest }, { replace: true })
})
const name = ref('')
const pending = ref(false)
const formError = ref('')

const loginError = computed(() => {
  const value = route.query.error
  if (typeof value !== 'string' || !value) return ''
  return te(`auth.loginErrors.${value}`) ? t(`auth.loginErrors.${value}`) : t('auth.loginErrors.unknown')
})

async function requestCode() {
  formError.value = ''
  pending.value = true
  try {
    await rpc('sign_in_codes.create', {
      email: email.value.trim(),
      ...(needsSetup.value && setupToken.value.trim() ? { setup_token: setupToken.value.trim() } : {}),
    })
    step.value = 'code'
    return true
  } catch (error) {
    formError.value = errorMessage(error)
    return false
  } finally {
    pending.value = false
  }
}

async function onVerified() {
  await auth.load()
  await navigateTo(safeRedirect(route.query.redirect))
}

/** Create the admin with the setup token; adding a passkey comes next. */
async function createAdmin() {
  formError.value = ''
  pending.value = true
  try {
    await rpc('setup_accounts.create', {
      setup_token: setupToken.value.trim(),
      email: email.value.trim(),
      ...(name.value.trim() ? { name: name.value.trim() } : {}),
    })
    await auth.load()
    await navigateTo('/finish-setup', { replace: true })
  } catch (error) {
    formError.value = errorMessage(error)
  } finally {
    pending.value = false
  }
}

function changeEmail() {
  step.value = 'email'
  formError.value = ''
}

// Passkeys (not during first-time setup: there is no account yet).
const passkeys = usePasskeys()
const passkeyPending = ref(false)

async function signInWithPasskey(autofill = false) {
  if (!autofill) passkeyPending.value = true
  formError.value = ''
  try {
    await passkeys.signIn(autofill)
    await onVerified()
  } catch (error) {
    // Dismissing the prompt, or the autofill request being replaced by the button, isn't an
    // error. Autofill is only an offer: when the browser cannot make it, say nothing.
    if (!autofill && !isPasskeyCancel(error)) formError.value = errorMessage(error)
  } finally {
    if (!autofill) passkeyPending.value = false
  }
}

// Offer saved passkeys in the email field's suggestions where the browser can.
onMounted(async () => {
  if (needsSetup.value || !(await passkeys.supportsAutofill())) return
  void signInWithPasskey(true)
})
onBeforeUnmount(() => passkeys.cancel())
</script>

<template>
  <AuthCodeStep v-if="step === 'code'" :email="email" :resend="requestCode" @verified="onVerified" @back="changeEmail" />
  <Card v-else>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">{{ needsSetup ? t('auth.setupTitle') : t('auth.signInTitle') }}</CardTitle>
      <CardDescription>{{ description }}</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-6">
      <Alert v-if="loginError" variant="destructive">
        <AlertDescription>{{ loginError }}</AlertDescription>
      </Alert>

      <AuthProviderButtons v-if="oidc" :name="oidc.display_name" :setup-token="needsSetup ? setupToken.trim() : undefined" :separator="emailEnabled || tokenSetup" />

      <p v-if="setupMethod === 'unavailable'" class="text-sm text-muted-foreground">{{ t('auth.noSetupMethod') }}</p>

      <form v-if="tokenSetup" class="flex flex-col gap-4" @submit.prevent="createAdmin">
        <FieldGroup>
          <Field>
            <FieldLabel for="setup-token">{{ t('auth.setupToken') }}</FieldLabel>
            <Input id="setup-token" v-model="setupToken" type="password" autocomplete="off" required />
            <FieldDescription>{{ t('auth.setupTokenHint') }}</FieldDescription>
          </Field>
          <Field>
            <FieldLabel for="email">{{ t('auth.email') }}</FieldLabel>
            <Input id="email" v-model="email" type="email" autocomplete="email" :placeholder="t('auth.emailPlaceholder')" required />
            <FieldDescription>{{ t('auth.tokenSetupEmailHint') }}</FieldDescription>
          </Field>
          <Field>
            <FieldLabel for="name">{{ t('auth.name') }}</FieldLabel>
            <Input id="name" v-model="name" maxlength="100" autocomplete="name" :placeholder="t('auth.namePlaceholder')" />
          </Field>
        </FieldGroup>
        <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
        <Button type="submit" :loading="pending">{{ t('auth.createAdminAccount') }}</Button>
      </form>

      <form v-if="emailEnabled" class="flex flex-col gap-4" @submit.prevent="requestCode">
        <FieldGroup>
          <Field>
            <FieldLabel for="email">{{ t('auth.email') }}</FieldLabel>
            <!-- "webauthn" lets the browser suggest saved passkeys here. -->
            <Input id="email" v-model="email" type="email" autocomplete="email webauthn" :placeholder="t('auth.emailPlaceholder')" required />
          </Field>
          <Field v-if="needsSetup && setupTokenRequired">
            <FieldLabel for="setup-token">{{ t('auth.setupToken') }}</FieldLabel>
            <Input id="setup-token" v-model="setupToken" type="password" autocomplete="off" required />
            <FieldDescription>{{ t('auth.setupTokenHint') }}</FieldDescription>
          </Field>
        </FieldGroup>
        <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
        <Button type="submit" :loading="pending">
          {{ needsSetup ? t('auth.createAdmin') : t('auth.continueWithEmail') }}
        </Button>
      </form>

      <Button v-if="!needsSetup && passkeys.supported.value" variant="outline" :disabled="passkeyPending" @click="signInWithPasskey()">
        <FingerprintIcon />{{ t('passkeys.signIn') }}
      </Button>
      <p v-if="formError && !emailEnabled && !tokenSetup" class="text-sm text-destructive" role="alert">{{ formError }}</p>
    </CardContent>
  </Card>
</template>
