<script setup lang="ts">
import { ChevronRightIcon, PencilIcon, Trash2Icon, XIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { Group, GroupMember, Person, SshAccessRule } from '~/types/api'

/**
 * One group: its members (people added by hand can be removed, people the identity provider put
 * here cannot), the provider group names that feed it, and the host groups that use it.
 */
definePageMeta({ header: false, requires: ['instance', 'read_groups'] })

const { t, locale } = useI18n()
const rpc = useRpc()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const errorMessage = useErrorMessage()

const id = computed(() => String(route.params.id))
const { data: group, error } = await useAsyncData(`group-${id.value}`, async () => {
  const res = await rpc('groups.get', { id: id.value })
  auth.remember(res.data)
  return res.data
})
if (error.value || !group.value) throw pageError(error.value, t('errorPage.notFoundTitle'))

useHead({ title: () => group.value?.name ?? t('groups.title') })

const canManage = computed(() => auth.can('instance', 'manage_groups'))

// Members, a page at a time.
const members = ref<GroupMember[]>([])
const membersCursor = ref<string | null>(null)
const membersLoading = ref(false)
async function loadMembers(more = false) {
  membersLoading.value = true
  try {
    const res = await rpc('group_members.list', { group_id: id.value, cursor: more ? (membersCursor.value ?? undefined) : undefined, limit: 50 })
    auth.remember(res.data)
    members.value = more ? [...members.value, ...res.data] : res.data
    membersCursor.value = res.next_cursor
  } finally {
    membersLoading.value = false
  }
}
await loadMembers()

async function reloadGroup() {
  const res = await rpc('groups.get', { id: id.value })
  auth.remember(res.data)
  group.value = res.data
  providerGroups.value = [...res.data.provider_groups]
}

const picked = ref<Person | null>(null)
const addMember = useAction(async (person: Person) => {
  await rpc('group_members.create', { group_id: id.value, user_id: person.id })
  toast.success(t('groups.detail.added', { name: person.name }))
  picked.value = null
  await Promise.all([loadMembers(), reloadGroup()])
})
watch(picked, (person) => {
  if (person) void addMember(person)
})

const removing = ref<GroupMember | null>(null)
const removeMember = useAction(async () => {
  if (!removing.value) return
  await rpc('group_members.delete', { group_id: id.value, user_id: removing.value.user_id })
  toast.success(t('groups.detail.removed', { name: removing.value.name }))
  removing.value = null
  await Promise.all([loadMembers(), reloadGroup()])
})

// Provider group names.
const providerGroups = ref<string[]>([...group.value!.provider_groups])
const providerError = ref('')
const providerChanged = computed(() => providerGroups.value.join('\n') !== group.value!.provider_groups.join('\n'))
const saveProviders = useAction(async () => {
  providerError.value = ''
  try {
    const res = await rpc('groups.update', { id: id.value, provider_groups: providerGroups.value })
    group.value = res.data
    providerGroups.value = [...res.data.provider_groups]
    toast.success(t('groups.detail.providersSaved'))
  } catch (error) {
    if (!(error instanceof RpcError) || error.status !== 400) throw error
    providerError.value = errorMessage(error)
  }
})

// Where the group is used.
const { data: rules } = await useAsyncData(
  `group-rules-${id.value}`,
  async () => {
    const all: SshAccessRule[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_access_rules.list', { group_id: id.value, cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return all
  },
  { default: () => [] as SshAccessRule[] },
)

const editOpen = ref(false)
const deleteOpen = ref(false)
const remove = useAction(async () => {
  await rpc('groups.delete', { id: id.value })
  toast.success(t('groups.detail.deleted', { name: group.value!.name }))
  await router.push('/settings/groups')
})
</script>

<template>
  <div v-if="group">
    <!-- Settings has its own header bar; the way back is a plain breadcrumb above the title. -->
    <nav class="mb-4 flex min-w-0 items-center gap-1.5 text-sm" :aria-label="t('groups.detail.back')">
      <NuxtLink to="/settings/groups" class="shrink-0 text-muted-foreground hover:text-foreground">{{ t('groups.detail.back') }}</NuxtLink>
      <ChevronRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
      <span class="truncate font-medium">{{ group.name }}</span>
    </nav>

    <div class="flex flex-col gap-6">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex min-w-0 flex-col gap-3">
          <h2 class="text-2xl font-semibold tracking-tight break-words">{{ group.name }}</h2>
          <p v-if="group.description" class="max-w-2xl text-sm text-muted-foreground">{{ group.description }}</p>
        </div>
        <div v-if="canManage" class="flex flex-wrap gap-2">
          <Button variant="outline" @click="editOpen = true"><PencilIcon />{{ t('groups.detail.edit') }}</Button>
          <Button variant="outline" class="text-destructive" @click="deleteOpen = true"><Trash2Icon />{{ t('groups.detail.delete') }}</Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('groups.detail.members') }}</CardTitle>
            <Badge variant="secondary" class="tabular-nums">{{ group.member_count }}</Badge>
          </div>
        </CardHeader>
        <CardContent class="flex flex-col gap-4">
          <PersonPicker v-if="canManage" v-model="picked" :placeholder="t('groups.detail.addMember')" :exclude="members.map((m) => m.user_id)" />
          <p v-if="!members.length" class="text-sm text-muted-foreground">{{ t('groups.detail.noMembers') }}</p>
          <ul v-else class="divide-y rounded-md border">
            <li v-for="member in members" :key="member.user_id" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
              <UserAvatar :name="member.name" class="size-8" />
              <span class="flex min-w-0 flex-1 flex-col">
                <span class="truncate font-medium">{{ member.name }}</span>
                <span class="truncate text-xs text-muted-foreground">{{ member.email }}</span>
              </span>
              <Badge v-if="member.source === 'oidc'" variant="outline" class="text-muted-foreground">{{ t('groups.detail.fromProvider') }}</Badge>
              <span class="text-xs text-muted-foreground">{{ timeAgo(member.added_at, locale) }}</span>
              <Button v-if="member.permissions.delete" variant="ghost" size="icon" class="size-8" :aria-label="t('groups.detail.remove', { name: member.name })" :title="t('groups.detail.remove', { name: member.name })" @click="removing = member"><XIcon class="size-4" /></Button>
            </li>
          </ul>
          <Button v-if="membersCursor" variant="outline" class="self-center" :loading="membersLoading" @click="loadMembers(true)">{{ t('common.loadMore') }}</Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-1.5">
            <CardTitle>{{ t('groups.detail.providerGroups') }}</CardTitle>
            <InfoTip :text="t('groups.detail.providerGroupsTip')" />
          </div>
        </CardHeader>
        <CardContent class="flex flex-col gap-4">
          <ChipInput id="group-providers" v-model="providerGroups" :placeholder="t('groups.detail.providerPlaceholder')" :error="providerError" :disabled="!canManage" mono />
          <div v-if="canManage" class="flex justify-end">
            <Button :disabled="!providerChanged" :loading="saveProviders.busy" @click="saveProviders()">{{ t('common.save') }}</Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{{ t('groups.detail.usedIn') }}</CardTitle>
        </CardHeader>
        <CardContent>
          <p v-if="!rules.length" class="text-sm text-muted-foreground">{{ t('groups.detail.notUsed') }}</p>
          <ul v-else class="divide-y rounded-md border">
            <li v-for="rule in rules" :key="rule.id" class="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-2.5 text-sm">
              <NuxtLink :to="`/ssh/host-groups/${rule.host_group.id}`" class="min-w-32 flex-1 truncate font-medium underline-offset-4 hover:underline">{{ rule.host_group.name }}</NuxtLink>
              <span class="flex flex-wrap gap-1.5">
                <Badge v-for="login in rule.logins" :key="login" variant="secondary" class="font-mono text-xs">{{ login }}</Badge>
                <Badge v-if="rule.own_username" variant="outline" class="text-muted-foreground">{{ t('sshRules.ownUsername') }}</Badge>
              </span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>

    <GroupEditDialog v-model:open="editOpen" :group="group" @saved="(next) => { group = next }" />

    <Dialog :open="!!removing" @update:open="(open) => !open && (removing = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('groups.detail.removeTitle', { name: removing?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('groups.detail.removeText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="removing = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="removeMember.busy" @click="removeMember()">{{ t('groups.detail.removeConfirm') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('groups.detail.deleteTitle', { name: group.name }) }}</DialogTitle>
          <DialogDescription>{{ t('groups.detail.deleteText') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="remove.busy" @click="remove()">{{ t('groups.detail.delete') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
