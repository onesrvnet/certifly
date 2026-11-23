<script setup lang="ts">
import { ChevronRightIcon, PencilIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { SshCertificate, SshHost, SshHostGroup } from '~/types/api'

/**
 * One SSH host: its names and keys, the host certificate it holds now and the ones before it.
 * Operators and admins edit or remove it; alert mails link here.
 */
definePageMeta({ header: false, requires: ['instance', 'read_ssh_hosts'] })

const { t, d, locale } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const id = computed(() => String(route.params.id))
const { data: host, error } = await useAsyncData(`ssh-host-${id.value}`, async () => {
  const res = await rpc('ssh_hosts.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !host.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

useHead({ title: () => host.value?.name ?? t('nav.sshHosts') })

const canManage = computed(() => auth.can('instance', 'manage_ssh_hosts'))

const { data: certificates, refresh: refreshCertificates } = await useAsyncData(
  `ssh-host-certs-${id.value}`,
  async () => {
    const all: SshCertificate[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_certificates.list', { host_id: id.value, kind: 'host', cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    auth.remember(all)
    return all
  },
  { default: () => [] as SshCertificate[] },
)
/** One valid certificate per host key; the one ending last is shown as the current one. */
const current = computed(() => certificates.value.filter((c) => c.status === 'active').sort((a, b) => b.valid_before.localeCompare(a.valid_before)))

const { data: hostGroups } = await useAsyncData(
  'ssh-host-groups-for-edit',
  async () => {
    if (!canManage.value) return []
    const all: SshHostGroup[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_host_groups.list', { cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return all
  },
  { default: () => [] as SshHostGroup[] },
)

const editOpen = ref(false)
function saved(next: SshHost) {
  host.value = next
  void refreshCertificates()
}

const revoking = ref<SshCertificate | null>(null)
const revokeOpen = computed({ get: () => !!revoking.value, set: (open) => { if (!open) revoking.value = null } })

const deleteOpen = ref(false)
const remove = useAction(async () => {
  await rpc('ssh_hosts.delete', { id: id.value })
  toast.success(t('sshHosts.detail.deleted', { name: host.value!.name }))
  await router.push('/ssh/hosts')
})

const keyType = (key: string) => key.trim().split(/\s+/)[0] ?? ''
</script>

<template>
  <div v-if="host">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('sshHosts.detail.back')">
        <NuxtLink to="/ssh/hosts" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('sshHosts.detail.back') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ host.name }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-3">
          <h2 class="text-2xl font-semibold tracking-tight break-words">{{ host.name }}</h2>
          <div class="flex flex-wrap gap-2">
            <MetaChip v-if="auth.can('instance', 'read_ssh_host_groups')" :label="t('sshHosts.detail.hostGroup')"><NuxtLink :to="`/ssh/host-groups/${host.host_group.id}`" class="text-primary underline-offset-4 hover:underline">{{ host.host_group.name }}</NuxtLink></MetaChip>
            <MetaChip v-else :label="t('sshHosts.detail.hostGroup')">{{ host.host_group.name }}</MetaChip>
            <MetaChip :label="t('sshHosts.detail.lastSeen')">{{ host.last_seen_at ? timeAgo(host.last_seen_at, locale) : t('sshHosts.row.neverSynced') }}</MetaChip>
          </div>
        </div>
        <div v-if="canManage" class="flex flex-wrap gap-2">
          <Button variant="outline" @click="editOpen = true"><PencilIcon />{{ t('sshHosts.detail.edit') }}</Button>
          <Button variant="outline" class="text-destructive" @click="deleteOpen = true"><Trash2Icon />{{ t('sshHosts.detail.delete') }}</Button>
        </div>
      </div>

      <div class="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>{{ t('sshHosts.detail.names') }}</CardTitle></CardHeader>
          <CardContent class="flex flex-wrap gap-1.5">
            <Badge v-for="name in host.hostnames" :key="name" variant="secondary" class="font-mono text-xs">{{ name }}</Badge>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{{ t('sshHosts.detail.keys') }}</CardTitle></CardHeader>
          <CardContent class="flex flex-col gap-3">
            <CaCopyField v-for="key in host.public_keys" :key="key" :label="keyType(key)" :value="key" />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>{{ t('sshHosts.detail.current') }}</CardTitle></CardHeader>
        <CardContent class="flex flex-col gap-4">
          <p v-if="!current.length" class="text-sm text-muted-foreground">{{ t('sshHosts.detail.noCertificate') }}</p>
          <div v-for="cert in current" :key="cert.id" class="flex min-w-0 flex-col gap-3">
            <CaCopyField :label="t('sshHosts.detail.certificate')" :value="cert.certificate" />
            <div class="flex flex-wrap gap-2">
              <MetaChip :label="t('sshHosts.detail.validUntil')">{{ d(new Date(cert.valid_before), { dateStyle: 'medium', timeStyle: 'short' }) }}</MetaChip>
              <MetaChip :label="t('sshHosts.detail.serial')"><span class="font-mono">{{ cert.serial }}</span></MetaChip>
              <MetaChip :label="t('sshHosts.detail.fingerprint')"><span class="font-mono">{{ cert.fingerprint }}</span></MetaChip>
            </div>
          </div>
        </CardContent>
      </Card>

      <section class="flex flex-col gap-3">
        <h3 class="text-lg font-semibold tracking-tight">{{ t('sshHosts.detail.history') }}</h3>
        <SshCertRows :rows="certificates" :empty="t('sshHosts.detail.noHistory')" @revoke="revoking = $event" />
      </section>
    </div>

    <SshHostDialog v-model:open="editOpen" :host="host" :host-groups="hostGroups" @saved="saved" />
    <SshRevokeDialog v-model:open="revokeOpen" :certificate="revoking" @revoked="refreshCertificates()" />

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshHosts.detail.deleteTitle', { name: host.name }) }}</DialogTitle>
          <DialogDescription>{{ t('sshHosts.detail.deleteText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('sshHosts.detail.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
