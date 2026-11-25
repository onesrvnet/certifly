<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { EllipsisIcon, UserPlusIcon, XIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { Invite, Member, Role } from '~/types/api'

/** People and invites (admins): change roles, deactivate and reactivate, invite and revoke. */
definePageMeta({ titleKey: 'settings.title', requires: ['instance', 'manage_users'] })

const { t, d, locale } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const showError = useErrorToast()
const errorMessage = useErrorMessage()

useHead({ title: () => t('users.title') })


const PAGE_SIZE = 25
const query = ref('')
const debouncedQuery = refDebounced(query, 300)
const includeDeactivated = ref(true)
const pager = useCursorPages(PAGE_SIZE)
const inviteOpen = ref(false)

watch([debouncedQuery, includeDeactivated], () => pager.reset())

const { data, pending, refresh } = await useAsyncData(
  'users',
  async () => {
    const res = await rpc('users.list', {
      query: debouncedQuery.value.trim() || undefined,
      include_deactivated: includeDeactivated.value,
      cursor: pager.cursor.value,
      limit: PAGE_SIZE,
    })
    auth.remember(res.data)
    // Admins always get the full rows.
    return { members: res.data as unknown as Member[], next_cursor: res.next_cursor }
  },
  { watch: [debouncedQuery, includeDeactivated, pager.cursor] },
)
const members = computed(() => data.value?.members ?? [])

const { data: invites, refresh: refreshInvites } = await useAsyncData(
  'invites',
  async () => {
    const res = await rpc('invites.list', { status: 'pending', limit: 100 })
    auth.remember(res.data)
    return res.data
  },
  { default: () => [] as Invite[] },
)

const busy = ref<string | null>(null)
/** The person whose SSH security keys are shown. */
const keysOf = ref<Member | null>(null)
/** The server refuses to remove the last admin; this says so next to the table, not just in a toast. */
const lastAdmin = ref(false)
const lastAdminMessage = errorMessage(new RpcError(409, 'last_admin', ''))

async function mutate(member: Member, action: () => Promise<unknown>, message: string) {
  busy.value = member.id
  lastAdmin.value = false
  try {
    await action()
    toast.success(message)
    await refresh()
  } catch (error) {
    if (error instanceof RpcError && error.code === 'last_admin') lastAdmin.value = true
    // Role changes and (de)activation need a recent confirmation; once given, try again.
    else showError(error, () => mutate(member, action, message))
    // Show what the server holds, e.g. the role select snaps back after a refusal.
    await refresh()
  } finally {
    busy.value = null
  }
}

const changeRole = (member: Member, role: Role) =>
  role !== member.role &&
  mutate(member, () => rpc('users.update', { id: member.id, role }), t('users.roleChanged', { name: member.name, role: t(`roles.${role}`) }))

const confirming = ref<Member | null>(null)
function deactivate() {
  const member = confirming.value
  confirming.value = null
  if (member) return mutate(member, () => rpc('users.update', { id: member.id, deactivated: true }), t('users.deactivatedToast', { name: member.name }))
}
const reactivate = (member: Member) =>
  mutate(member, () => rpc('users.update', { id: member.id, deactivated: false }), t('users.reactivatedToast', { name: member.name }))

// The SSH username: what the person is called as a login on hosts.
const usernameTarget = ref<Member | null>(null)
const usernameDraft = ref('')
const usernameError = ref('')
function openUsername(member: Member) {
  usernameTarget.value = member
  usernameDraft.value = member.username ?? ''
  usernameError.value = ''
}
const saveUsername = useAction(async () => {
  const member = usernameTarget.value
  if (!member) return
  usernameError.value = ''
  try {
    await rpc('users.update', { id: member.id, username: usernameDraft.value.trim() })
    toast.success(t('users.usernameSaved', { name: member.name }))
    usernameTarget.value = null
    await refresh()
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409)) throw error
    usernameError.value = errorMessage(error)
  }
})

const revoking = ref<Invite | null>(null)
const revokeInvite = useAction(async () => {
  const invite = revoking.value
  if (!invite) return
  await rpc('invites.delete', { id: invite.id })
  revoking.value = null
  toast.success(t('users.inviteRevoked'))
  await refreshInvites()
})
</script>

<template>
  <div class="flex flex-col gap-10">
    <SettingsSection :title="t('users.title')" :description="t('users.description')">
      <Alert v-if="lastAdmin" variant="destructive" class="relative pr-10">
        <AlertTitle>{{ t('users.lastAdminTitle') }}</AlertTitle>
        <AlertDescription>{{ lastAdminMessage }}</AlertDescription>
        <Button variant="ghost" size="icon" class="absolute top-2 right-2 size-7" :aria-label="t('common.dismiss')" @click="lastAdmin = false"><XIcon /></Button>
      </Alert>

      <div class="flex flex-wrap items-center gap-2">
        <Input v-model="query" type="search" class="w-full sm:max-w-sm sm:flex-1" :placeholder="t('users.searchPlaceholder')" :aria-label="t('common.search')" />
        <label class="flex items-center gap-2 text-sm">
          <Switch v-model="includeDeactivated" />{{ t('users.showDeactivated') }}
        </label>
        <Button class="ml-auto" @click="inviteOpen = true"><UserPlusIcon />{{ t('users.invite') }}</Button>
      </div>
      <InviteDialog v-model:open="inviteOpen" @invited="refreshInvites()" />

      <div class="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{{ t('users.name') }}</TableHead>
              <TableHead class="hidden w-40 md:table-cell">{{ t('users.sshUsername') }}</TableHead>
              <TableHead class="w-40">{{ t('users.role') }}</TableHead>
              <TableHead class="w-28">{{ t('users.status') }}</TableHead>
              <TableHead class="w-32">{{ t('users.lastActive') }}</TableHead>
              <TableHead class="w-14 text-right"><span class="sr-only">{{ t('users.actions') }}</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="member in members" :key="member.id" :class="pending && 'opacity-60'">
              <TableCell>
                <div class="flex items-center gap-3">
                  <UserAvatar :name="member.name" class="size-8" />
                  <div class="flex min-w-0 flex-col">
                    <span class="truncate font-medium">
                      {{ member.name }}
                      <span v-if="member.id === auth.user?.id" class="font-normal text-muted-foreground">({{ t('common.you') }})</span>
                    </span>
                    <span class="truncate text-xs text-muted-foreground">{{ member.email }}</span>
                  </div>
                </div>
              </TableCell>
              <TableCell class="hidden md:table-cell">
                <span v-if="member.username" class="font-mono text-sm">{{ member.username }}</span>
                <span v-else class="text-sm text-muted-foreground">—</span>
              </TableCell>
              <TableCell>
                <Select
                  v-if="auth.can(member.id, 'change_role') && !member.deleted_at"
                  :model-value="member.role"
                  :disabled="busy === member.id"
                  @update:model-value="(role) => changeRole(member, role as Role)"
                >
                  <SelectTrigger size="sm" class="w-32" :aria-label="t('users.role')"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="role in (['admin', 'operator', 'viewer'] as const)" :key="role" :value="role">{{ t(`roles.${role}`) }}</SelectItem>
                  </SelectContent>
                </Select>
                <span v-else class="text-sm">{{ t(`roles.${member.role}`) }}</span>
              </TableCell>
              <TableCell>
                <Badge v-if="member.deleted_at" variant="destructive" :title="d(new Date(member.deleted_at))">{{ t('users.deactivated') }}</Badge>
                <Badge v-else variant="secondary">{{ t('users.active') }}</Badge>
              </TableCell>
              <TableCell class="text-sm text-muted-foreground">
                {{ member.last_active_at ? timeAgo(member.last_active_at, locale) : '—' }}
              </TableCell>
              <TableCell class="text-right">
                <DropdownMenu>
                  <DropdownMenuTrigger as-child>
                    <Button variant="ghost" size="icon-sm" :icon="EllipsisIcon" :loading="busy === member.id" :aria-label="t('users.more')" />
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem v-if="auth.can(member.id, 'set_username') && !member.deleted_at" @select="openUsername(member)">{{ t('users.editUsername') }}</DropdownMenuItem>
                    <DropdownMenuItem @select="keysOf = member">{{ t('users.securityKeys') }}</DropdownMenuItem>
                    <DropdownMenuItem v-if="member.deleted_at && auth.can(member.id, 'reactivate')" @select="reactivate(member)">{{ t('users.reactivate') }}</DropdownMenuItem>
                    <DropdownMenuItem v-else-if="!member.deleted_at && auth.can(member.id, 'deactivate')" variant="destructive" @select="confirming = member">{{ t('users.deactivate') }}</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </TableCell>
            </TableRow>
            <TableRow v-if="!members.length && !pending">
              <TableCell colspan="6" class="h-24 text-center text-muted-foreground">{{ t('users.empty') }}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>

      <div v-if="pager.index.value > 0 || data?.next_cursor" class="flex items-center justify-between text-sm text-muted-foreground">
        <span>{{ t('common.pageRange', { from: pager.offset.value + 1, to: pager.offset.value + members.length }) }}</span>
        <div class="flex gap-2">
          <Button variant="outline" size="sm" :disabled="pager.index.value === 0" @click="pager.previous()">{{ t('common.previous') }}</Button>
          <Button variant="outline" size="sm" :disabled="!data?.next_cursor" @click="pager.next(data?.next_cursor)">{{ t('common.next') }}</Button>
        </div>
      </div>
    </SettingsSection>

    <SettingsSection :title="t('users.invitesTitle')" :description="t('users.invitesDescription')">
      <ul v-if="invites.length" class="divide-y rounded-md border">
        <li v-for="invite in invites" :key="invite.id" class="flex items-center gap-3 px-4 py-3 text-sm">
          <div class="flex min-w-0 flex-1 flex-col">
            <span class="truncate font-medium">{{ invite.email }}</span>
            <span class="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
              <MetaChip :label="t('users.roleChip')">{{ t(`roles.${invite.role}`) }}</MetaChip>
              <span>{{ t('users.inviteExpires', { date: d(new Date(invite.expires_at), { dateStyle: 'medium' }) }) }}</span>
            </span>
          </div>
          <Button v-if="auth.can(invite.id, 'revoke')" variant="outline" size="sm" @click="revoking = invite">{{ t('users.inviteRevoke') }}</Button>
        </li>
      </ul>
      <p v-else class="rounded-md border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">{{ t('users.invitesEmpty') }}</p>
    </SettingsSection>

    <Dialog :open="!!keysOf" @update:open="(open) => !open && (keysOf = null)">
      <DialogContent class="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{{ t('sshSecurityKeys.title') }}</DialogTitle>
          <DialogDescription>{{ t('sshSecurityKeys.userDescription', { name: keysOf?.name ?? '' }) }}</DialogDescription>
        </DialogHeader>
        <SshSecurityKeys v-if="keysOf" :user="keysOf" />
      </DialogContent>
    </Dialog>

    <Dialog :open="!!confirming" @update:open="(open) => !open && (confirming = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('users.deactivateTitle', { name: confirming?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('users.deactivateDescription') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="confirming = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" @click="deactivate">{{ t('users.deactivate') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!usernameTarget" @update:open="(open) => !open && (usernameTarget = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('users.usernameTitle', { name: usernameTarget?.name ?? '' }) }}</DialogTitle>
          <DialogDescription class="sr-only">{{ t('users.sshUsername') }}</DialogDescription>
        </DialogHeader>
        <form class="flex flex-col gap-4" @submit.prevent="saveUsername()">
          <Field :data-invalid="!!usernameError || undefined">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="user-ssh-username">{{ t('users.sshUsername') }}</FieldLabel>
              <InfoTip :text="t('users.usernameTip')" />
            </div>
            <Input id="user-ssh-username" v-model="usernameDraft" maxlength="40" required autocomplete="off" spellcheck="false" class="font-mono" />
            <FieldError v-if="usernameError">{{ usernameError }}</FieldError>
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" @click="usernameTarget = null">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="saveUsername.busy" :disabled="!usernameDraft.trim()">{{ t('common.save') }}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!revoking" @update:open="(open) => !open && (revoking = null)">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ t('users.inviteRevokeTitle', { email: revoking?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('users.inviteRevokeDescription') }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="revoking = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="revokeInvite.busy" @click="revokeInvite()">{{ t('users.inviteRevoke') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
