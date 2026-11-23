<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { Group, SshAccessRule } from '~/types/api'

/**
 * Add or edit an access rule of a host group: which group may log in, as which local users. The
 * principals the certificates will carry show live below the logins.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{
  hostGroup: { id: string; slug: string }
  rule: SshAccessRule | null
  groups: Group[]
  /** Groups that already have a rule here; they cannot be picked again. */
  takenGroupIds: string[]
}>()
const emit = defineEmits<{ saved: [] }>()
const { t } = useI18n()
const rpc = useRpc()
const errorMessage = useErrorMessage()

const LOGIN = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/
const groupId = ref('')
const logins = ref<string[]>([])
const ownUsername = ref(false)
const formError = ref('')

const available = computed(() => props.groups.filter((g) => !props.takenGroupIds.includes(g.id) || g.id === props.rule?.group.id))
const principals = computed(() => [...rulePrincipals(props.hostGroup.slug, logins.value), ...(ownUsername.value ? [`${props.hostGroup.slug}:~${t('sshRules.dialog.ownPrincipal')}`] : [])])
const ready = computed(() => !!groupId.value && (logins.value.length > 0 || ownUsername.value))
const checkLogin = (value: string) => (LOGIN.test(value) ? null : t('sshRules.dialog.invalidLogin'))

watch(open, (isOpen) => {
  formError.value = ''
  if (!isOpen) return
  groupId.value = props.rule?.group.id ?? available.value[0]?.id ?? ''
  logins.value = [...(props.rule?.logins ?? [])]
  ownUsername.value = props.rule?.own_username ?? false
})

const submit = useAction(async () => {
  formError.value = ''
  try {
    if (props.rule) await rpc('ssh_access_rules.update', { id: props.rule.id, logins: logins.value, own_username: ownUsername.value })
    else await rpc('ssh_access_rules.create', { host_group_id: props.hostGroup.id, group_id: groupId.value, logins: logins.value, own_username: ownUsername.value })
    toast.success(t('sshRules.dialog.saved'))
    open.value = false
    emit('saved')
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409 && error.status !== 404)) throw error
    formError.value = errorMessage(error)
  }
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ rule ? t('sshRules.dialog.editTitle') : t('sshRules.dialog.createTitle') }}</DialogTitle>
        <DialogDescription class="sr-only">{{ t('sshRules.dialog.createTitle') }}</DialogDescription>
      </DialogHeader>
      <form class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
        <FieldGroup>
          <Field>
            <FieldLabel for="rule-group">{{ t('sshRules.dialog.group') }}</FieldLabel>
            <p v-if="!available.length" class="text-sm text-muted-foreground">{{ t('sshRules.dialog.noGroups') }}</p>
            <Select v-else v-model="groupId" :disabled="!!rule">
              <SelectTrigger id="rule-group" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="group in available" :key="group.id" :value="group.id">{{ group.name }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <ChipInput id="rule-logins" v-model="logins" :label="t('sshRules.dialog.logins')" :placeholder="t('sshRules.dialog.loginsPlaceholder')" :check="checkLogin" mono />
          <Field orientation="horizontal">
            <Checkbox id="rule-own" v-model="ownUsername" />
            <div class="flex items-center gap-1.5">
              <FieldLabel for="rule-own" class="font-normal">{{ t('sshRules.dialog.ownUsername') }}</FieldLabel>
              <InfoTip :text="t('sshRules.dialog.ownUsernameTip')" />
            </div>
          </Field>
          <Field>
            <FieldLabel>{{ t('sshRules.dialog.principals') }}</FieldLabel>
            <div class="flex min-h-6 flex-wrap gap-1.5">
              <Badge v-for="principal in principals" :key="principal" variant="secondary" class="font-mono text-xs">{{ principal }}</Badge>
              <span v-if="!principals.length" class="text-sm text-muted-foreground">{{ t('sshRules.dialog.noPrincipals') }}</span>
            </div>
          </Field>
          <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ t('common.save') }}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
