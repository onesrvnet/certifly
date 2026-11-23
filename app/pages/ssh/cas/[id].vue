<script setup lang="ts">
import { ChevronRightIcon, DownloadIcon, PencilIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { SshHostGroup } from '~/types/api'

/**
 * One SSH CA: its public key and revocation list URL, the lines for hosts that run without the
 * CLI, and the host groups that use it. Admins rename and delete it; the key itself never changes.
 */
definePageMeta({ header: false, requires: ['instance', 'read_ssh_cas'] })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const errorMessage = useErrorMessage()

const id = computed(() => String(route.params.id))
const { data: ca, error } = await useAsyncData(`ssh-ca-${id.value}`, async () => {
  const res = await rpc('ssh_cas.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !ca.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

useHead({ title: () => ca.value?.name ?? t('nav.sshCas') })

const can = (ability: string) => auth.can(ca.value?.id, ability)

const { data: hostGroups } = await useAsyncData(
  `ssh-ca-groups-${id.value}`,
  async () => {
    if (!auth.can('instance', 'read_ssh_host_groups')) return []
    const all: SshHostGroup[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_host_groups.list', { ssh_ca_id: id.value, cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return all
  },
  { default: () => [] as SshHostGroup[] },
)

const origin = useRequestURL().origin
const krlUrl = computed(() => `${origin}${ca.value!.krl_url}`)
/** What a host without the CLI needs: the CA key and revocation list on disk, and sshd told about both. */
const sshdConfig = computed(() => `TrustedUserCAKeys /etc/ssh/certifly-${ca.value!.slug}.pub\nRevokedKeys /etc/ssh/certifly-${ca.value!.slug}.krl`)
/**
 * Trust host certificates from this CA only for the host names its host groups allow; with no host
 * group yet, a placeholder shows where the patterns go.
 */
const knownHosts = computed(() => {
  const patterns = [...new Set(hostGroups.value.flatMap((group) => group.host_patterns))]
  return `@cert-authority ${patterns.length ? patterns.join(',') : '*.example.com'} ${ca.value!.public_key}`
})

// Rename.
const editOpen = ref(false)
const editName = ref('')
const editDescription = ref('')
function openEdit() {
  editName.value = ca.value!.name
  editDescription.value = ca.value!.description
  editOpen.value = true
}
const editError = ref('')
const save = useAction(async () => {
  editError.value = ''
  try {
    const res = await rpc('ssh_cas.update', { id: id.value, name: editName.value.trim(), description: editDescription.value.trim() })
    auth.remember(res.data)
    ca.value = res.data
    editOpen.value = false
    toast.success(t('sshCas.detail.saved'))
  } catch (error) {
    if (!(error instanceof RpcError) || error.status !== 400) throw error
    editError.value = errorMessage(error)
  }
})

const deleteOpen = ref(false)
const remove = useAction(async () => {
  await rpc('ssh_cas.delete', { id: id.value })
  toast.success(t('sshCas.detail.deleted', { name: ca.value!.name }))
  await router.push('/ssh/cas')
})
</script>

<template>
  <div v-if="ca">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('sshCas.detail.back')">
        <NuxtLink to="/ssh/cas" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('sshCas.detail.back') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ ca.name }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto flex w-full max-w-4xl flex-col gap-6 p-4 md:p-10">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-3">
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="text-2xl font-semibold tracking-tight break-words">{{ ca.name }}</h2>
            <Badge variant="outline" class="font-mono text-muted-foreground">{{ ca.slug }}</Badge>
          </div>
          <div class="flex flex-wrap gap-2">
            <MetaChip :label="t('sshCas.chips.key')">{{ sshKeyLabel(ca.key_algorithm) }}</MetaChip>
            <MetaChip :label="t('sshCas.chips.fingerprint')"><span class="font-mono">{{ ca.fingerprint }}</span></MetaChip>
            <MetaChip :label="t('sshCas.chips.source')">{{ t(`sshCas.source.${ca.source}`) }}</MetaChip>
          </div>
        </div>
        <div v-if="can('update') || can('delete')" class="flex flex-wrap gap-2">
          <Button v-if="can('update')" variant="outline" @click="openEdit"><PencilIcon />{{ t('sshCas.detail.edit') }}</Button>
          <Button v-if="can('delete')" variant="outline" class="text-destructive" @click="deleteOpen = true"><Trash2Icon />{{ t('sshCas.detail.delete') }}</Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{{ t('sshCas.detail.publicKey') }}</CardTitle>
          <CardAction>
            <Button variant="outline" size="sm" @click="downloadText(`${ca.slug}.pub`, `${ca.public_key}\n`, 'text/plain')"><DownloadIcon />{{ t('sshCas.detail.downloadPub') }}</Button>
          </CardAction>
        </CardHeader>
        <CardContent class="flex flex-col gap-4">
          <SshCodeBlock :label="ca.public_key.split(' ')[0] ?? ''" :value="ca.public_key" />
          <CaCopyField :label="t('sshCas.detail.krl')" :value="krlUrl" />
        </CardContent>
      </Card>

      <FormCard :title="t('sshCas.detail.manual')" :info="t('sshCas.detail.manualTip')">
        <div class="flex flex-col gap-4">
          <SshCodeBlock :label="t('sshCas.detail.sshdConfig')" :value="sshdConfig" />
          <SshCodeBlock :label="t('sshCas.detail.knownHosts')" :value="knownHosts" />
        </div>
      </FormCard>

      <div v-if="hostGroups.length" class="flex flex-wrap items-center gap-2">
        <span class="text-sm text-muted-foreground">{{ t('sshCas.detail.hostGroups') }}</span>
        <NuxtLink v-for="group in hostGroups" :key="group.id" :to="`/ssh/host-groups/${group.id}`">
          <Badge variant="outline" class="hover:bg-accent">{{ group.name }}</Badge>
        </NuxtLink>
      </div>
    </div>

    <Dialog v-model:open="editOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshCas.detail.editTitle') }}</DialogTitle>
          <DialogDescription class="sr-only">{{ t('sshCas.detail.editTitle') }}</DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="save()">
          <FieldGroup>
            <Field>
              <FieldLabel for="ca-edit-name">{{ t('sshCas.new.name') }}</FieldLabel>
              <Input id="ca-edit-name" v-model="editName" maxlength="100" required />
            </Field>
            <Field>
              <FieldLabel for="ca-edit-description">{{ t('sshCas.new.description') }}</FieldLabel>
              <Textarea id="ca-edit-description" v-model="editDescription" rows="2" maxlength="1000" />
            </Field>
            <p v-if="editError" class="text-sm text-destructive" role="alert">{{ editError }}</p>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" @click="editOpen = false">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="save.busy" :disabled="!editName.trim()">{{ t('common.save') }}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshCas.detail.deleteTitle', { name: ca.name }) }}</DialogTitle>
          <DialogDescription>{{ t('sshCas.detail.deleteText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('sshCas.detail.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
