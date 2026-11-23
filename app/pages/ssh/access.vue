<script setup lang="ts">
import { KeyRoundIcon, LogOutIcon, ServerIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CliSession, SshCertificate } from '~/types/api'

/**
 * My SSH access: the host groups the signed-in person may log in to, with the logins and
 * lifetimes they get, their current certificates, their CLI sign-ins, and how to get the CLI.
 */
definePageMeta({ titleKey: 'nav.sshAccess' })

const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const duration = (seconds: number) => durationLabel(seconds, t)

useHead({ title: () => t('nav.sshAccess') })

const signOpen = ref(false)

const { data: access, error } = await useAsyncData('ssh-access', () => rpc('ssh_access.get'))
if (error.value || !access.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

/** Reachable hosts per host group, counted over every page. */
const { data: hostCounts } = await useLazyAsyncData(
  'ssh-access-hosts',
  async () => {
    const counts: Record<string, number> = {}
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_hosts.reachable', { cursor, limit: 500 })
      for (const host of res.data) counts[host.host_group.id] = (counts[host.host_group.id] ?? 0) + 1
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return counts
  },
  { default: () => ({}) as Record<string, number> },
)

/** The person's valid certificates, newest ending last per host group. */
const { data: certificates, refresh: refreshCertificates } = await useLazyAsyncData(
  'ssh-access-certificates',
  async () => {
    const res = await rpc('ssh_certificates.list', { kind: 'user', status: 'active', user_id: auth.user?.id, limit: 200 })
    auth.remember(res.data)
    return res.data
  },
  { default: () => [] as SshCertificate[] },
)
const certificateOf = (hostGroupId: string) =>
  certificates.value.filter((cert) => cert.host_group?.id === hostGroupId).sort((a, b) => b.valid_before.localeCompare(a.valid_before))[0] ?? null
const remaining = (cert: SshCertificate) => durationLabel(Math.max(0, secondsUntil(cert.valid_before)), t)

const { data: sessions, refresh: refreshSessions } = await useLazyAsyncData(
  'ssh-access-sessions',
  async () => (await rpc('cli_sessions.list')).data,
  { default: () => [] as CliSession[] },
)
const signOut = useAction(async (session: CliSession) => {
  await rpc('cli_sessions.delete', { id: session.id })
  toast.success(t('ssh.access.signedOut', { name: session.machine.hostname }))
  await refreshSessions()
})

const INSTALL = 'brew install onesrvnet/tap/certifly'
</script>

<template>
  <div class="mx-auto flex w-full max-w-4xl flex-col gap-6 p-4 md:p-10">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <MetaChip :label="t('ssh.access.username')"><span class="font-mono">{{ access!.user.username }}</span></MetaChip>
      <Button @click="signOpen = true"><KeyRoundIcon />{{ t('ssh.sign.button') }}</Button>
    </div>

    <div v-if="!access!.host_groups.length" class="flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-primary"><ServerIcon class="size-6" /></span>
      <h3 class="text-lg font-medium">{{ t('ssh.access.empty') }}</h3>
      <p class="max-w-md text-sm text-muted-foreground">{{ t('ssh.access.emptyHint') }}</p>
    </div>

    <Card v-for="group in access!.host_groups" :key="group.id">
      <CardHeader>
        <div class="flex min-w-0 flex-wrap items-center gap-2">
          <CardTitle class="break-words">{{ group.name }}</CardTitle>
          <Badge variant="outline" class="font-mono text-muted-foreground">{{ group.slug }}</Badge>
          <Badge v-if="group.key_policy !== 'any'" variant="outline" class="border-info/30 bg-info-soft text-info">{{ t(`ssh.keyPolicy.badge.${group.key_policy}`) }}</Badge>
        </div>
      </CardHeader>
      <CardContent class="flex flex-col gap-3">
        <div class="flex flex-wrap items-center gap-x-2 gap-y-2">
          <MetaChip :label="t('ssh.access.logInAs')">
            <span class="flex flex-wrap gap-1"><span v-for="login in group.logins" :key="login" class="font-mono">{{ login }}</span></span>
          </MetaChip>
          <MetaChip :label="t('ssh.access.upTo')">{{ duration(group.max_ttl_seconds) }}</MetaChip>
        </div>
        <div v-if="hostCounts[group.id] || certificateOf(group.id)" class="flex flex-wrap items-center gap-2">
          <MetaChip v-if="hostCounts[group.id]" :label="t('ssh.access.hosts')">{{ hostCounts[group.id] }}</MetaChip>
          <MetaChip v-if="certificateOf(group.id)" :label="t('ssh.access.certificate')">{{ t('ssh.access.validFor', { time: remaining(certificateOf(group.id)!) }) }}</MetaChip>
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle>{{ t('ssh.access.sessions') }}</CardTitle>
      </CardHeader>
      <CardContent>
        <p v-if="!sessions.length" class="text-sm text-muted-foreground">{{ t('ssh.access.noSessions') }}</p>
        <ul v-else class="divide-y rounded-md border">
          <li v-for="session in sessions" :key="session.id" class="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5 text-sm">
            <span class="min-w-32 flex-1 truncate font-medium">{{ session.machine.hostname }}</span>
            <MetaChip :label="t('ssh.access.system')">{{ session.machine.os }}</MetaChip>
            <MetaChip :label="t('ssh.access.timeLeft')">{{ durationLabel(Math.max(0, secondsUntil(session.expires_at)), t) }}</MetaChip>
            <Button v-if="session.permissions.delete" variant="outline" size="sm" :loading="signOut.busy" @click="signOut(session)"><LogOutIcon />{{ t('ssh.access.signOut') }}</Button>
          </li>
        </ul>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <div class="flex items-center gap-1.5">
          <CardTitle>{{ t('ssh.access.getCli') }}</CardTitle>
          <InfoTip :text="t('ssh.access.getCliTip')" />
        </div>
      </CardHeader>
      <CardContent>
        <CaCopyField :label="t('ssh.access.install')" :value="INSTALL" />
      </CardContent>
    </Card>

    <SshSignDialog v-model:open="signOpen" @signed="refreshCertificates()" />
  </div>
</template>
