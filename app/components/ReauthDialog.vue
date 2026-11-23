<script setup lang="ts">
import { FingerprintIcon, KeyRoundIcon, MailIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { RpcOutput } from '~/types/api'

/**
 * Step-up: prove who you are again before a sensitive action, by an emailed code (when the
 * instance can send mail), a passkey or the identity provider (when one is configured). One
 * instance lives in the layout and is opened through the reauth store, which tells the waiting
 * action whether to retry. The provider flow leaves the page and comes back with
 * `?reauth=done` or `?reauth_error=<code>`, which is reported here.
 */
const { t, te } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const reauth = useReauthStore()
const route = useRoute()
const router = useRouter()
const errorMessage = useErrorMessage()
const passkeys = usePasskeys()

type AuthConfig = RpcOutput<'auth_config.get'>['data']
const config = ref<AuthConfig | null>(null)

const sent = ref(false)
const code = ref('')
const pending = ref(false)
const error = ref('')

/** Whether the person has a passkey at all; checked each time the dialog opens, since they may have just added one. */
const hasPasskey = ref(false)

const emailEnabled = computed(() => config.value?.email_enabled ?? false)
const oidc = computed(() => (config.value?.oidc.enabled ? config.value.oidc : null))
const passkeyAvailable = computed(() => passkeys.supported.value && hasPasskey.value)
const noMethod = computed(() => !!config.value && !emailEnabled.value && !oidc.value && !passkeyAvailable.value)

watch(
  () => reauth.open,
  async (open) => {
    if (!open) return
    sent.value = false
    code.value = ''
    error.value = ''
    try {
      const [cfg, list] = await Promise.all([
        config.value ? Promise.resolve(config.value) : rpc('auth_config.get').then((res) => res.data),
        rpc('passkeys.list').then((res) => res.data),
      ])
      config.value = cfg
      hasPasskey.value = list.length > 0
    } catch (err) {
      error.value = errorMessage(err)
    }
  },
)

function onOpenChange(open: boolean) {
  if (!open) reauth.finish(false)
}

async function finish() {
  await auth.load()
  toast.success(t('reauth.done'))
  reauth.finish(true)
}

async function sendCode() {
  pending.value = true
  error.value = ''
  try {
    await rpc('reauthentications.create', { method: 'email' })
    sent.value = true
  } catch (err) {
    error.value = errorMessage(err)
  } finally {
    pending.value = false
  }
}

// `autofocus` does not fire for an input that appears after the dialog opened, and the input
// stays disabled until the request settles, so focus it once it can take focus.
watch([sent, pending], async ([isSent, isPending]) => {
  if (!isSent || isPending) return
  await nextTick()
  document.querySelector<HTMLInputElement>('input#reauth-code')?.focus()
})

async function verifyCode() {
  if (code.value.length !== 6 || pending.value) return
  pending.value = true
  error.value = ''
  try {
    await rpc('reauthentications.verify', { method: 'email', code: code.value })
    await finish()
  } catch (err) {
    error.value = errorMessage(err)
    code.value = ''
  } finally {
    pending.value = false
  }
}

async function usePasskey() {
  pending.value = true
  error.value = ''
  try {
    const res = await rpc('reauthentications.create', { method: 'passkey' })
    if (res.data.method !== 'passkey') return
    await passkeys.reauthenticate(res.data.options as Parameters<typeof passkeys.reauthenticate>[0])
    await finish()
  } catch (err) {
    if (!isPasskeyCancel(err)) error.value = errorMessage(err)
  } finally {
    pending.value = false
  }
}

/** The provider flow is a full page load; the action that asked is not retried, the person repeats it. */
const oidcHref = computed(() => `/auth/oidc/reauth?return_to=${encodeURIComponent(route.fullPath)}`)

// Coming back from the provider.
onMounted(async () => {
  const { reauth: done, reauth_error: failed, ...rest } = route.query
  if (done === undefined && failed === undefined) return
  await router.replace({ query: rest })
  if (done === 'done') {
    await auth.load()
    toast.success(t('reauth.done'))
  } else if (typeof failed === 'string') {
    const key = te(`errors.${failed}`) ? `errors.${failed}` : te(`auth.loginErrors.${failed}`) ? `auth.loginErrors.${failed}` : 'errors.unknown'
    toast.error(t(key))
  }
})
</script>

<template>
  <!-- Asked for from inside other dialogs too; its portal comes first in the page, so it needs a higher layer to stay on top. -->
  <Dialog :open="reauth.open" @update:open="onOpenChange">
    <DialogContent class="z-60 sm:max-w-md" overlay-class="z-60">
      <DialogHeader>
        <DialogTitle>{{ t('reauth.dialogTitle') }}</DialogTitle>
        <DialogDescription>{{ t('reauth.dialogDescription') }}</DialogDescription>
      </DialogHeader>
      <div class="flex flex-col gap-4">
        <form v-if="sent" class="flex flex-col items-center gap-4" @submit.prevent="verifyCode">
          <p class="text-sm text-muted-foreground">{{ t('reauth.codeSent', { email: auth.user?.email ?? '' }) }}</p>
          <Label for="reauth-code" class="sr-only">{{ t('auth.code') }}</Label>
          <InputOTP id="reauth-code" v-model="code" :disabled="pending" :maxlength="6" inputmode="numeric" autocomplete="one-time-code" autofocus @complete="verifyCode">
            <InputOTPGroup>
              <InputOTPSlot v-for="i in 6" :key="i" :index="i - 1" />
            </InputOTPGroup>
          </InputOTP>
          <Button type="submit" class="w-full" :loading="pending" :disabled="code.length !== 6">{{ t('auth.verify') }}</Button>
        </form>
        <template v-else>
          <Button v-if="passkeyAvailable" variant="outline" :disabled="pending || !config" @click="usePasskey"><FingerprintIcon />{{ t('reauth.passkeyMethod') }}</Button>
          <Button v-if="emailEnabled" variant="outline" :loading="pending" @click="sendCode"><MailIcon />{{ t('reauth.emailMethod') }}</Button>
          <Button v-if="oidc" variant="outline" :disabled="pending" as-child>
            <a :href="oidcHref" @click="reauth.finish(false)"><KeyRoundIcon />{{ t('reauth.oidcMethod', { provider: oidc.display_name }) }}</a>
          </Button>
          <p v-if="noMethod" class="text-center text-sm text-muted-foreground">{{ t('reauth.noMethod') }}</p>
        </template>
        <p v-if="error" class="text-center text-sm text-destructive" role="alert">{{ error }}</p>
      </div>
    </DialogContent>
  </Dialog>
</template>
