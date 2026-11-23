<script setup lang="ts">
import { CopyIcon, DownloadIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { Person, RpcOutput } from '~/types/api'

/**
 * Sign my key: pick a host group, paste a public key, choose how long the certificate lasts, and
 * get the certificate back to copy or download. Operators and admins may sign for someone else;
 * then every host group is offered and the server applies that person's access rules.
 */
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ signed: [] }>()
const { t, d } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()
const errorMessage = useErrorMessage()
const duration = (seconds: number) => durationLabel(seconds, t)

interface Choice {
  id: string
  name: string
  slug: string
  key_policy: SshKeyPolicy
  default_ttl_seconds: number
  max_ttl_seconds: number
}

const own = ref<Choice[]>([])
const all = ref<Choice[]>([])
const loading = ref(false)
const hostGroupId = ref('')
const publicKey = ref('')
const hours = ref<number | string>('')
const forPerson = ref<Person | null>(null)
const formError = ref('')
const result = ref<RpcOutput<'ssh_user_certificates.sign'>['data'] | null>(null)

const canSignForOthers = computed(() => auth.can('instance', 'sign_ssh_for_others'))
const choices = computed(() => (forPerson.value ? all.value : own.value))
const chosen = computed(() => choices.value.find((c) => c.id === hostGroupId.value) ?? null)
const attestedOnly = computed(() => chosen.value?.key_policy === 'sk_attested')
const maxHours = computed(() => (chosen.value ? chosen.value.max_ttl_seconds / 3600 : SSH_USER_TTL_MAX_HOURS))
const ttlSeconds = computed(() => Math.round(Number(hours.value) * 3600))
const ttlValid = computed(() => !!chosen.value && Number.isFinite(ttlSeconds.value) && ttlSeconds.value >= 60 && ttlSeconds.value <= chosen.value.max_ttl_seconds)
const ready = computed(() => !!chosen.value && !attestedOnly.value && publicKey.value.trim().length > 0 && ttlValid.value)

async function load() {
  loading.value = true
  try {
    const mine = await rpc('ssh_access.get')
    own.value = mine.host_groups.map((g) => ({ id: g.id, name: g.name, slug: g.slug, key_policy: g.key_policy, default_ttl_seconds: g.default_ttl_seconds, max_ttl_seconds: g.max_ttl_seconds }))
    if (canSignForOthers.value && auth.can('instance', 'read_ssh_host_groups')) {
      const groups: Choice[] = []
      let cursor: string | undefined
      do {
        const res = await rpc('ssh_host_groups.list', { cursor, limit: 200 })
        groups.push(...res.data.map((g) => ({ id: g.id, name: g.name, slug: g.slug, key_policy: g.key_policy, default_ttl_seconds: g.user_ttl_default_seconds, max_ttl_seconds: g.user_ttl_max_seconds })))
        cursor = res.next_cursor ?? undefined
      } while (cursor)
      all.value = groups
    }
    pickDefault()
  } catch (error) {
    formError.value = errorMessage(error)
  } finally {
    loading.value = false
  }
}

function pickDefault() {
  if (!choices.value.some((c) => c.id === hostGroupId.value)) hostGroupId.value = choices.value[0]?.id ?? ''
}

watch(open, (isOpen) => {
  if (!isOpen) {
    // Nothing of a signed certificate or a pasted key stays around.
    result.value = null
    publicKey.value = ''
    return
  }
  result.value = null
  formError.value = ''
  publicKey.value = ''
  forPerson.value = null
  hostGroupId.value = ''
  void load()
})
watch(forPerson, pickDefault)
// A new host group brings its own default lifetime.
watch(chosen, (group) => {
  if (group) hours.value = group.default_ttl_seconds / 3600
})

const submit = useAction(async () => {
  if (!chosen.value) return
  formError.value = ''
  try {
    const res = await rpc('ssh_user_certificates.sign', {
      host_group_id: chosen.value.id,
      public_key: publicKey.value.trim(),
      ttl_seconds: ttlSeconds.value,
      for_user_id: forPerson.value?.id,
    })
    result.value = res.data
    emit('signed')
  } catch (error) {
    if (!(error instanceof RpcError) || error.status >= 500 || error.status === 401) throw error
    formError.value = errorMessage(error)
  }
})

async function copy() {
  if (!result.value) return
  await navigator.clipboard.writeText(result.value.certificate)
  toast.success(t('common.copied'))
}

const fileName = computed(() => certFileName(publicKey.value))
const download = () => result.value && downloadText(fileName.value, `${result.value.certificate}\n`, 'text/plain')
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-xl">
      <DialogHeader>
        <div class="flex items-center gap-1.5">
          <DialogTitle>{{ t('ssh.sign.title') }}</DialogTitle>
          <InfoTip :text="t('ssh.sign.cliTip')" />
        </div>
        <DialogDescription class="sr-only">{{ t('ssh.sign.title') }}</DialogDescription>
      </DialogHeader>

      <div v-if="result" class="flex min-w-0 flex-col gap-4">
        <Field>
          <FieldLabel for="sign-cert">{{ t('ssh.sign.certificate') }}</FieldLabel>
          <Textarea id="sign-cert" :model-value="result.certificate" readonly rows="6" class="font-mono text-xs break-all" @focus="($event.target as HTMLTextAreaElement).select()" />
        </Field>
        <div class="flex flex-wrap gap-2">
          <MetaChip :label="t('ssh.sign.keyId')"><span class="font-mono">{{ result.key_id }}</span></MetaChip>
          <MetaChip :label="t('ssh.sign.validUntil')">{{ d(new Date(result.valid_before), { dateStyle: 'medium', timeStyle: 'short' }) }}</MetaChip>
        </div>
        <div class="flex flex-wrap gap-1.5">
          <Badge v-for="principal in result.principals" :key="principal" variant="secondary" class="font-mono text-xs">{{ principal }}</Badge>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="copy"><CopyIcon />{{ t('common.copy') }}</Button>
          <Button variant="outline" @click="download"><DownloadIcon />{{ t('ssh.sign.download', { name: fileName }) }}</Button>
          <Button @click="open = false">{{ t('common.done') }}</Button>
        </DialogFooter>
      </div>

      <form v-else class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
        <FieldGroup>
          <Field v-if="canSignForOthers">
            <FieldLabel for="sign-for">{{ t('ssh.sign.forPerson') }}</FieldLabel>
            <PersonPicker id="sign-for" v-model="forPerson" clearable :placeholder="t('ssh.sign.forMyself')" />
          </Field>

          <Field>
            <FieldLabel for="sign-group">{{ t('ssh.sign.hostGroup') }}</FieldLabel>
            <Skeleton v-if="loading" class="h-9 w-full" />
            <p v-else-if="!choices.length" class="text-sm text-muted-foreground">{{ t('ssh.sign.noHostGroups') }}</p>
            <Select v-else v-model="hostGroupId">
              <SelectTrigger id="sign-group" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="choice in choices" :key="choice.id" :value="choice.id">{{ choice.name }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>

          <Alert v-if="attestedOnly">
            <AlertDescription>{{ t('ssh.sign.attestedOnly') }}</AlertDescription>
          </Alert>

          <Field :data-invalid="!!formError || undefined">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="sign-key">{{ t('ssh.sign.publicKey') }}</FieldLabel>
              <InfoTip :text="chosen?.key_policy === 'sk' ? t('ssh.sign.publicKeyTipSk') : t('ssh.sign.publicKeyTip')" />
            </div>
            <Textarea id="sign-key" v-model="publicKey" rows="4" required spellcheck="false" autocomplete="off" class="font-mono text-xs break-all" :placeholder="t('ssh.sign.publicKeyPlaceholder')" />
          </Field>

          <Field v-if="chosen">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="sign-ttl">{{ t('ssh.sign.lifetime') }}</FieldLabel>
              <InfoTip :text="t('ssh.sign.lifetimeTip', { default: duration(chosen.default_ttl_seconds), max: duration(chosen.max_ttl_seconds) })" />
            </div>
            <div class="flex items-center gap-2">
              <Input id="sign-ttl" v-model="hours" type="number" min="0.1" :max="maxHours" step="any" required class="w-28" />
              <span class="text-sm text-muted-foreground">{{ t('ssh.units.hours') }}</span>
            </div>
          </Field>

          <p v-if="formError" class="text-sm text-destructive" role="alert">{{ formError }}</p>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ t('ssh.sign.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
