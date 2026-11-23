<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import { toast } from 'vue-sonner'

import type { RpcOutput } from '~/types/api'

type Verified = RpcOutput<'sign_in_codes.verify'>['data']

/**
 * Second step of email sign-in and signup: enter the 6-digit code that was mailed.
 * `resend` asks for a new code (the caller knows which request to repeat).
 */
const props = defineProps<{ email: string; resend: () => Promise<boolean> }>()
const emit = defineEmits<{ verified: [data: Verified]; back: [] }>()

const { t } = useI18n()
const rpc = useRpc()
const errorMessage = useErrorMessage()

const code = ref('')
const pending = ref(false)
const formError = ref('')

const RESEND_SECONDS = 30
const cooldown = ref(RESEND_SECONDS)
const { pause, resume } = useIntervalFn(() => {
  cooldown.value = Math.max(0, cooldown.value - 1)
  if (cooldown.value === 0) pause()
}, 1000)

async function resend() {
  if (cooldown.value > 0) return
  if (!(await props.resend())) return
  code.value = ''
  cooldown.value = RESEND_SECONDS
  resume()
  toast.success(t('auth.resent'))
}

// Codes are single-use: @complete, Enter and paste can all trigger verify, so share one
// in-flight attempt and never surface a late failure once we're signed in.
let inflight: Promise<void> | null = null
let signedIn = false

function verify() {
  if (code.value.length !== 6 || signedIn) return inflight
  return (inflight ??= (async () => {
    formError.value = ''
    pending.value = true
    try {
      const { data } = await rpc('sign_in_codes.verify', { email: props.email.trim(), code: code.value })
      signedIn = true
      emit('verified', data)
    } catch (error) {
      if (!signedIn) {
        formError.value = errorMessage(error)
        code.value = ''
      }
    } finally {
      // Signed in: stay busy while the next page loads, which can take a moment.
      if (!signedIn) pending.value = false
      inflight = null
    }
  })())
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">{{ t('auth.codeTitle') }}</CardTitle>
      <CardDescription>{{ t('auth.codeDescription', { email }) }}</CardDescription>
    </CardHeader>
    <CardContent>
      <form class="flex flex-col items-center gap-4" @submit.prevent="verify">
        <Label for="code" class="sr-only">{{ t('auth.code') }}</Label>
        <InputOTP id="code" v-model="code" :disabled="pending" :maxlength="6" inputmode="numeric" autocomplete="one-time-code" autofocus @complete="verify">
          <InputOTPGroup>
            <InputOTPSlot v-for="i in 6" :key="i" :index="i - 1" />
          </InputOTPGroup>
        </InputOTP>
        <p v-if="formError" class="text-center text-sm text-destructive" role="alert">{{ formError }}</p>
        <Button type="submit" class="w-full" :loading="pending" :disabled="code.length !== 6">{{ t('auth.verify') }}</Button>
        <div class="flex w-full flex-col gap-1">
          <Button type="button" variant="ghost" size="sm" :disabled="pending || cooldown > 0" @click="resend">
            {{ cooldown > 0 ? t('auth.resendIn', { seconds: cooldown }) : t('auth.resend') }}
          </Button>
          <Button type="button" variant="link" size="sm" :disabled="pending" @click="emit('back')">{{ t('auth.differentEmail') }}</Button>
        </div>
      </form>
    </CardContent>
  </Card>
</template>
