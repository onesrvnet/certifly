<script setup lang="ts">
import { CircleCheckIcon, CircleXIcon, TriangleAlertIcon } from '@lucide/vue'

/**
 * Confirms a sign-in started by the certifly CLI: shows the machine and the code the CLI printed,
 * and approves or denies. Signing in first and coming back here is handled by the sign-in redirect.
 */
definePageMeta({ layout: 'auth', titleKey: 'cliLogin.title' })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()

useHead({ title: () => t('cliLogin.title') })

const id = computed(() => String(route.params.id))
const { data: login, error } = await useAsyncData(`cli-login-${id.value}`, async () => (await rpc('cli_logins.get', { login_id: id.value })).data)
// An expired or unknown login is a 404: the page says so instead of showing an error page.
if (error.value && errorStatus(error.value) !== 404) throw pageError(error.value, t('errorPage.notFoundTitle'))

/** What the person has done here: nothing yet, or approved or denied. */
const outcome = ref<'approved' | 'denied' | null>(null)
const state = computed(() => outcome.value ?? (login.value && login.value.status !== 'pending' ? (login.value.status === 'approved' ? 'approved' : 'denied') : null))

const approve = useAction(async () => {
  await rpc('cli_logins.approve', { login_id: id.value })
  outcome.value = 'approved'
})
const deny = useAction(async () => {
  await rpc('cli_logins.deny', { login_id: id.value })
  outcome.value = 'denied'
})
</script>

<template>
  <Card v-if="!login">
    <CardHeader>
      <CardTitle class="flex items-center gap-2"><TriangleAlertIcon class="size-5 text-warning" />{{ t('cliLogin.expiredTitle') }}</CardTitle>
    </CardHeader>
    <CardContent>
      <Button as-child variant="outline"><NuxtLink to="/">{{ t('errorPage.goHome') }}</NuxtLink></Button>
    </CardContent>
  </Card>

  <Card v-else-if="state">
    <CardHeader>
      <CardTitle class="flex items-center gap-2">
        <CircleCheckIcon v-if="state === 'approved'" class="size-5 text-success" />
        <CircleXIcon v-else class="size-5 text-muted-foreground" />
        {{ t(`cliLogin.${state}Title`) }}
      </CardTitle>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <p class="text-sm text-muted-foreground">{{ t('cliLogin.closeTab') }}</p>
      <Button as-child variant="outline" class="self-start"><NuxtLink to="/">{{ t('errorPage.goHome') }}</NuxtLink></Button>
    </CardContent>
  </Card>

  <Card v-else>
    <CardHeader>
      <CardTitle>{{ t('cliLogin.title') }}</CardTitle>
    </CardHeader>
    <CardContent class="flex flex-col gap-6">
      <dl class="flex flex-col gap-3 text-sm">
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('cliLogin.machine') }}</dt>
          <dd class="min-w-0 truncate font-medium">{{ t('cliLogin.machineValue', { hostname: login.machine.hostname, os: login.machine.os }) }}</dd>
        </div>
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('cliLogin.code') }}</dt>
          <dd class="font-mono text-lg font-semibold tracking-widest">{{ login.user_code }}</dd>
        </div>
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('cliLogin.valid') }}</dt>
          <dd class="font-medium">{{ t('cliLogin.validValue') }}</dd>
        </div>
      </dl>
      <div class="flex justify-end gap-2">
        <Button variant="outline" :loading="deny.busy" :disabled="approve.busy" @click="deny()">{{ t('cliLogin.deny') }}</Button>
        <Button :loading="approve.busy" :disabled="deny.busy" @click="approve()">{{ t('cliLogin.approve') }}</Button>
      </div>
    </CardContent>
  </Card>
</template>
