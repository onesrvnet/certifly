<script setup lang="ts">
import { ChevronRightIcon, EllipsisIcon, PlusIcon, Trash2Icon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { Group, SshAccessRule, SshCa, SshHost, SshHostGroup } from '~/types/api'

/**
 * One host group: who may log in as whom (access), its hosts, join tokens for new hosts, and
 * the settings. Admins change what they may; operators read.
 */
definePageMeta({ header: false, requires: ['instance', 'read_ssh_host_groups'] })

const { t } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const errorMessage = useErrorMessage()

const id = computed(() => String(route.params.id))
const { data: group, error } = await useAsyncData(`ssh-host-group-${id.value}`, async () => {
  const res = await rpc('ssh_host_groups.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !group.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

useHead({ title: () => group.value?.name ?? t('nav.sshHostGroups') })
useHead({ htmlAttrs: { style: 'scroll-padding: 5rem 0 5.5rem' } })

const canManage = computed(() => auth.can('instance', 'manage_ssh_host_groups'))
const canReadRules = computed(() => auth.can('instance', 'read_groups'))
const canReadTokens = computed(() => auth.can('instance', 'read_ssh_join_tokens'))

const TABS = computed(() => [...(canReadRules.value ? ['access'] : []), 'hosts', ...(canReadTokens.value ? ['tokens'] : []), 'settings'])
const tab = computed({
  get: () => (typeof route.query.tab === 'string' && TABS.value.includes(route.query.tab) ? route.query.tab : TABS.value[0]!),
  set: (value: string) => router.replace({ query: { ...route.query, tab: value } }),
})

// Access rules.
const { data: rules, refresh: refreshRules } = await useAsyncData(
  `ssh-host-group-rules-${id.value}`,
  async () => {
    if (!canReadRules.value) return []
    const all: SshAccessRule[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_access_rules.list', { host_group_id: id.value, cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    auth.remember(all)
    return all
  },
  { default: () => [] as SshAccessRule[] },
)
const { data: groups } = await useAsyncData(
  'ssh-host-group-groups',
  async () => {
    if (!canReadRules.value) return []
    const all: Group[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('groups.list', { cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return all
  },
  { default: () => [] as Group[] },
)
const ruleOpen = ref(false)
const editingRule = ref<SshAccessRule | null>(null)
const deletingRule = ref<SshAccessRule | null>(null)
function openRule(rule: SshAccessRule | null) {
  editingRule.value = rule
  ruleOpen.value = true
}
const removeRule = useAction(async () => {
  if (!deletingRule.value) return
  await rpc('ssh_access_rules.delete', { id: deletingRule.value.id })
  toast.success(t('sshRules.deleted'))
  deletingRule.value = null
  await refreshRules()
})

// Hosts, a page at a time.
const hosts = ref<SshHost[]>([])
const hostsCursor = ref<string | null>(null)
const hostsLoading = ref(false)
async function loadHosts(more = false) {
  hostsLoading.value = true
  try {
    const res = await rpc('ssh_hosts.list', { host_group_id: id.value, cursor: more ? (hostsCursor.value ?? undefined) : undefined, limit: 50 })
    auth.remember(res.data)
    hosts.value = more ? [...hosts.value, ...res.data] : res.data
    hostsCursor.value = res.next_cursor
  } finally {
    hostsLoading.value = false
  }
}
await loadHosts()

// Settings.
const { data: cas } = await useAsyncData('ssh-host-group-cas', async () => (await rpc('ssh_cas.list', { limit: 200 })).data, { default: () => [] as SshCa[] })
const form = ref(hostGroupFormFrom(group.value!))
const errors = ref<Partial<Record<HostGroupField, string>>>({})
const formError = ref('')

function replace(next: SshHostGroup) {
  auth.remember(next)
  group.value = next
  form.value = hostGroupFormFrom(next)
}
function reset() {
  form.value = hostGroupFormFrom(group.value!)
  errors.value = {}
  formError.value = ''
}

const save = useAction(async () => {
  errors.value = {}
  formError.value = ''
  try {
    const res = await rpc('ssh_host_groups.update', { id: id.value, name: form.value.name.trim(), ...hostGroupSettings(form.value) })
    replace(res.data)
    toast.success(t('sshHostGroups.detail.saved'))
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    const field = hostGroupErrorField(error)
    if (field) errors.value = { [field]: errorMessage(error) }
    else formError.value = errorMessage(error)
  }
})

const deleteOpen = ref(false)
const remove = useAction(async () => {
  await rpc('ssh_host_groups.delete', { id: id.value })
  toast.success(t('sshHostGroups.detail.deleted', { name: group.value!.name }))
  await router.push('/ssh/host-groups')
})
</script>

<template>
  <div v-if="group">
    <PageHeader>
      <nav class="flex min-w-0 items-center gap-1.5" :aria-label="t('sshHostGroups.detail.back')">
        <NuxtLink to="/ssh/host-groups" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('sshHostGroups.detail.back') }}</NuxtLink>
        <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
        <h1 class="truncate font-medium">{{ group.name }}</h1>
      </nav>
    </PageHeader>

    <div class="mx-auto flex w-full max-w-5xl flex-col gap-6 p-4 md:p-10">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-3">
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="text-2xl font-semibold tracking-tight break-words">{{ group.name }}</h2>
            <Badge variant="outline" class="font-mono text-muted-foreground">{{ group.slug }}</Badge>
          </div>
          <div class="flex flex-wrap gap-2">
            <MetaChip :label="t('sshHostGroups.chips.ca')"><NuxtLink :to="`/ssh/cas/${group.ca.id}`" class="text-primary underline-offset-4 hover:underline">{{ group.ca.name }}</NuxtLink></MetaChip>
            <MetaChip v-if="group.host_patterns.length" :label="t('sshHostGroups.chips.patterns')"><span class="font-mono">{{ group.host_patterns.join(', ') }}</span></MetaChip>
            <MetaChip :label="t('sshHostGroups.chips.hosts')">{{ group.host_count }}</MetaChip>
            <MetaChip :label="t('sshHostGroups.chips.key')">{{ t(`ssh.keyPolicy.short.${group.key_policy}`) }}</MetaChip>
          </div>
        </div>
        <Button v-if="canManage" variant="outline" class="text-destructive" @click="deleteOpen = true"><Trash2Icon />{{ t('sshHostGroups.detail.delete') }}</Button>
      </div>

      <Tabs v-model="tab" class="gap-6">
        <div class="-mx-4 overflow-x-auto px-4 md:mx-0 md:px-0">
          <TabsList>
            <TabsTrigger v-for="name in TABS" :key="name" :value="name" class="px-3">{{ t(`sshHostGroups.tabs.${name}`) }}</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent v-if="canReadRules" value="access" class="flex flex-col gap-4">
          <div v-if="canManage" class="flex justify-end">
            <Button @click="openRule(null)"><PlusIcon />{{ t('sshRules.add') }}</Button>
          </div>
          <p v-if="!rules.length" class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">{{ t('sshRules.empty') }}</p>
          <div v-else class="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{{ t('sshRules.group') }}</TableHead>
                  <TableHead>{{ t('sshRules.logInAs') }}</TableHead>
                  <TableHead v-if="canManage" class="w-14 text-right"><span class="sr-only">{{ t('sshRules.actions') }}</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="rule in rules" :key="rule.id">
                  <TableCell class="font-medium"><NuxtLink :to="`/settings/groups/${rule.group.id}`" class="underline-offset-4 hover:underline">{{ rule.group.name }}</NuxtLink></TableCell>
                  <TableCell>
                    <span class="flex flex-wrap gap-1.5">
                      <Badge v-for="login in rule.logins" :key="login" variant="secondary" class="font-mono text-xs">{{ login }}</Badge>
                      <Badge v-if="rule.own_username" variant="outline" class="text-muted-foreground">{{ t('sshRules.ownUsername') }}</Badge>
                    </span>
                  </TableCell>
                  <TableCell v-if="canManage" class="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger as-child>
                        <Button variant="ghost" size="icon-sm" :icon="EllipsisIcon" :aria-label="t('sshRules.actions')" />
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem @select="openRule(rule)">{{ t('sshRules.edit') }}</DropdownMenuItem>
                        <DropdownMenuItem variant="destructive" @select="deletingRule = rule">{{ t('sshRules.delete') }}</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        <TabsContent value="hosts" class="flex flex-col gap-4">
          <p v-if="!hosts.length" class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">{{ t('sshHosts.emptyInGroup') }}</p>
          <SshHostRows v-else :hosts="hosts" />
          <Button v-if="hostsCursor" variant="outline" class="self-center" :loading="hostsLoading" @click="loadHosts(true)">{{ t('common.loadMore') }}</Button>
        </TabsContent>

        <TabsContent v-if="canReadTokens" value="tokens">
          <SshJoinTokens :host-group="group" />
        </TabsContent>

        <TabsContent value="settings">
          <form class="flex flex-col gap-6" @submit.prevent="save()">
            <Alert v-if="formError" class="border-danger/40 bg-danger-soft text-danger">
              <AlertDescription class="text-foreground">{{ formError }}</AlertDescription>
            </Alert>
            <SshHostGroupForm v-model="form" :cas="cas" mode="edit" :errors="errors" :disabled="!canManage" />
            <div v-if="canManage" class="sticky bottom-0 z-10 flex flex-wrap justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur supports-[backdrop-filter]:bg-background/80">
              <Button type="button" variant="outline" @click="reset">{{ t('sshHostGroups.detail.reset') }}</Button>
              <Button type="submit" :loading="save.busy">{{ t('common.save') }}</Button>
            </div>
          </form>
        </TabsContent>
      </Tabs>
    </div>

    <SshRuleDialog v-model:open="ruleOpen" :host-group="group" :rule="editingRule" :groups="groups" :taken-group-ids="rules.map((r) => r.group.id)" @saved="refreshRules()" />

    <Dialog :open="!!deletingRule" @update:open="(open) => !open && (deletingRule = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshRules.deleteTitle', { group: deletingRule?.group.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('sshRules.deleteText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deletingRule = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="removeRule.busy" @click="removeRule()">{{ t('sshRules.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('sshHostGroups.detail.deleteTitle', { name: group.name }) }}</DialogTitle>
          <DialogDescription>{{ t('sshHostGroups.detail.deleteText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('sshHostGroups.detail.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
