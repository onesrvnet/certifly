<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { SshHost, SshHostGroup } from '~/types/api'

/**
 * Add or edit a host by hand: its host group, its names (they must match the group's patterns)
 * and its host keys as authorized_keys lines. Hosts with the certifly CLI enrol themselves with a
 * join token instead.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ host: SshHost | null; hostGroups: SshHostGroup[]; defaultHostGroupId?: string }>()
const emit = defineEmits<{ saved: [host: SshHost] }>()
const { t } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const errorMessage = useErrorMessage()

const hostGroupId = ref('')
const name = ref('')
const hostnames = ref<string[]>([])
const keys = ref('')
const formError = ref('')

const keyLines = computed(() => keys.value.split('\n').map((line) => line.trim()).filter(Boolean))
const ready = computed(() => !!hostGroupId.value && hostnames.value.length > 0 && keyLines.value.length > 0)
const NAME = /^[a-z0-9*]([a-z0-9.*-]*[a-z0-9])?$/
const checkName = (value: string) => (NAME.test(value) ? null : t('sshHosts.dialog.invalidName'))

watch(open, (isOpen) => {
  formError.value = ''
  if (!isOpen) return
  hostGroupId.value = props.host?.host_group.id ?? props.defaultHostGroupId ?? props.hostGroups[0]?.id ?? ''
  name.value = props.host?.name ?? ''
  hostnames.value = [...(props.host?.hostnames ?? [])]
  keys.value = (props.host?.public_keys ?? []).join('\n')
})

const patterns = computed(() => props.hostGroups.find((g) => g.id === hostGroupId.value)?.host_patterns ?? [])

const submit = useAction(async () => {
  formError.value = ''
  try {
    const res = props.host
      ? await rpc('ssh_hosts.update', { id: props.host.id, name: name.value.trim() || undefined, host_group_id: hostGroupId.value, hostnames: hostnames.value, public_keys: keyLines.value })
      : await rpc('ssh_hosts.create', { host_group_id: hostGroupId.value, name: name.value.trim() || undefined, hostnames: hostnames.value, public_keys: keyLines.value })
    auth.remember(res.data)
    toast.success(t(props.host ? 'sshHosts.dialog.saved' : 'sshHosts.dialog.added', { name: res.data.name }))
    open.value = false
    emit('saved', res.data)
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409 && error.status !== 404)) throw error
    formError.value = errorMessage(error)
  }
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ host ? t('sshHosts.dialog.editTitle') : t('sshHosts.dialog.addTitle') }}</DialogTitle>
        <DialogDescription class="sr-only">{{ t('sshHosts.dialog.addTitle') }}</DialogDescription>
      </DialogHeader>
      <form class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
        <FieldGroup>
          <Field>
            <FieldLabel for="host-group">{{ t('sshHosts.dialog.hostGroup') }}</FieldLabel>
            <Select v-model="hostGroupId">
              <SelectTrigger id="host-group" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="group in hostGroups" :key="group.id" :value="group.id">{{ group.name }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <ChipInput
            id="host-names"
            v-model="hostnames"
            :label="t('sshHosts.dialog.hostNames')"
            :info="patterns.length ? t('sshHosts.dialog.hostNamesTip', { patterns: patterns.join(', ') }) : t('sshHosts.dialog.hostNamesTipNone')"
            :placeholder="t('sshHosts.dialog.hostNamesPlaceholder')"
            :check="checkName"
            lowercase
            mono
          />
          <Field>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="host-name">{{ t('sshHosts.dialog.name') }}</FieldLabel>
              <InfoTip :text="t('sshHosts.dialog.nameTip')" />
            </div>
            <Input id="host-name" v-model="name" maxlength="253" autocomplete="off" :placeholder="hostnames[0] ?? ''" />
          </Field>
          <Field>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="host-keys">{{ t('sshHosts.dialog.keys') }}</FieldLabel>
              <InfoTip :text="t('sshHosts.dialog.keysTip')" />
            </div>
            <Textarea id="host-keys" v-model="keys" rows="4" required spellcheck="false" autocomplete="off" class="font-mono text-xs break-all" :placeholder="t('sshHosts.dialog.keysPlaceholder')" />
          </Field>
          <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ host ? t('common.save') : t('sshHosts.dialog.add') }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
