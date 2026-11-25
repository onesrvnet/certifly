<script setup lang="ts">
import { CircleCheckIcon, CircleXIcon, InfoIcon, TriangleAlertIcon } from '@lucide/vue'

/**
 * Approves a YubiKey the certifly CLI registered: shows the code the CLI printed, the machine
 * and the key, and approves (with a fresh confirmation) or denies.
 */
definePageMeta({ layout: 'auth', titleKey: 'securityKeyApproval.title' })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()

useHead({ title: () => t('securityKeyApproval.title') })

const id = computed(() => String(route.params.id))
const { data: enrollment, error } = await useAsyncData(`security-key-enrollment-${id.value}`, async () => (await rpc('ssh_security_key_enrollments.get', { enrollment_id: id.value })).data)
// An expired or unknown registration is a 404: the page says so instead of showing an error page.
if (error.value && errorStatus(error.value) !== 404) throw pageError(error.value, t('errorPage.notFoundTitle'))

const outcome = ref<'approved' | 'denied' | null>(null)
const state = computed(() => outcome.value ?? (enrollment.value && enrollment.value.status !== 'pending' ? enrollment.value.status : null))

const approve = useAction(async () => {
  await rpc('ssh_security_key_enrollments.approve', { enrollment_id: id.value })
  outcome.value = 'approved'
})
const deny = useAction(async () => {
  await rpc('ssh_security_key_enrollments.deny', { enrollment_id: id.value })
  outcome.value = 'denied'
})
</script>

<template>
  <Card v-if="!enrollment">
    <CardHeader>
      <CardTitle class="flex items-center gap-2"><TriangleAlertIcon class="size-5 text-warning" />{{ t('securityKeyApproval.expiredTitle') }}</CardTitle>
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
        {{ t(`securityKeyApproval.${state}Title`) }}
      </CardTitle>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <p class="text-sm text-muted-foreground">{{ t('securityKeyApproval.closeTab') }}</p>
      <Button as-child variant="outline" class="self-start"><NuxtLink to="/settings/security">{{ t('sshSecurityKeys.title') }}</NuxtLink></Button>
    </CardContent>
  </Card>

  <Card v-else>
    <CardHeader>
      <CardTitle>{{ t('securityKeyApproval.title') }}</CardTitle>
    </CardHeader>
    <CardContent class="flex flex-col gap-6">
      <dl class="flex flex-col gap-3 text-sm">
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('securityKeyApproval.code') }}</dt>
          <dd class="font-mono text-lg font-semibold tracking-widest">{{ enrollment.user_code }}</dd>
        </div>
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('securityKeyApproval.machine') }}</dt>
          <dd class="min-w-0 truncate font-medium">{{ t('securityKeyApproval.machineValue', { hostname: enrollment.machine.hostname, os: enrollment.machine.os }) }}</dd>
        </div>
        <div class="flex items-center justify-between gap-4">
          <dt class="shrink-0 text-muted-foreground">{{ t('securityKeyApproval.key') }}</dt>
          <dd class="min-w-0 font-mono text-xs break-all text-right">{{ enrollment.fingerprint }}</dd>
        </div>
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('securityKeyApproval.model') }}</dt>
          <dd class="flex flex-wrap items-center justify-end gap-2 font-medium">
            {{ enrollment.model ?? t('sshSecurityKeys.securityKey') }}
            <Badge v-if="enrollment.attested" variant="outline" class="border-success/30 bg-success-soft text-success">{{ t('sshSecurityKeys.genuine') }}</Badge>
          </dd>
        </div>
        <div class="flex items-center justify-between gap-4">
          <dt class="text-muted-foreground">{{ t('securityKeyApproval.name') }}</dt>
          <dd class="min-w-0 truncate font-medium">{{ enrollment.name }}</dd>
        </div>
      </dl>
      <Alert>
        <InfoIcon />
        <AlertDescription>{{ t('securityKeyApproval.hint') }}</AlertDescription>
      </Alert>
      <div class="flex justify-end gap-2">
        <Button variant="outline" :loading="deny.busy" :disabled="approve.busy" @click="deny()">{{ t('securityKeyApproval.deny') }}</Button>
        <Button :loading="approve.busy" :disabled="deny.busy" @click="approve()">{{ t('securityKeyApproval.approve') }}</Button>
      </div>
      <!-- This layout has no re-authentication dialog of its own; approving asks for one. -->
      <ReauthDialog />
    </CardContent>
  </Card>
</template>
