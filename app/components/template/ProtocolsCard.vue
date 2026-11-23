<script setup lang="ts">
import { KeyRoundIcon, PlusIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { OnceSecret } from '~/components/OnceSecretDialog.vue'
import type { Template } from '~/types/api'

/**
 * Automated enrollment for one template: ACME (with its external account binding keys) and EST
 * (with its basic-auth credentials). Each can be switched on here; new credentials are shown once.
 */
const props = defineProps<{ template: Template }>()
const emit = defineEmits<{ updated: [template: Template] }>()
const { t, locale } = useI18n()
const rpc = useRpc()
const auth = useAuthStore()

const canManage = computed(() => auth.can(props.template.id, 'update') && props.template.status === 'active')

type Kind = 'acme' | 'est'
interface Credential {
  id: string
  name: string
  /** The EAB key id or the EST username. */
  handle: string
  last_used_at: string | null
  revoked_at: string | null
  can_revoke: boolean
}

const { data: eabKeys, refresh: refreshEab } = await useLazyAsyncData(
  `template-eab-${props.template.id}`,
  async () => {
    if (!props.template.allow_acme) return []
    const res = await rpc('acme_eab_keys.list', { template_id: props.template.id })
    auth.remember(res.data)
    return res.data.map((k): Credential => ({ id: k.id, name: k.name, handle: k.kid, last_used_at: k.last_used_at, revoked_at: k.revoked_at, can_revoke: auth.can(k.id, 'revoke') }))
  },
  { default: () => [] as Credential[], watch: [() => props.template.allow_acme] },
)
const { data: estCredentials, refresh: refreshEst } = await useLazyAsyncData(
  `template-est-${props.template.id}`,
  async () => {
    if (!props.template.allow_est) return []
    const res = await rpc('est_credentials.list', { template_id: props.template.id })
    auth.remember(res.data)
    return res.data.map((c): Credential => ({ id: c.id, name: c.name, handle: c.username, last_used_at: c.last_used_at, revoked_at: c.revoked_at, can_revoke: auth.can(c.id, 'revoke') }))
  },
  { default: () => [] as Credential[], watch: [() => props.template.allow_est] },
)
const credentials = (kind: Kind) => (kind === 'acme' ? eabKeys.value : estCredentials.value)

const toggle = useAction(async (kind: Kind, on: boolean) => {
  const res = await rpc('templates.update', { id: props.template.id, ...(kind === 'acme' ? { allow_acme: on } : { allow_est: on }) })
  emit('updated', res.data)
  toast.success(t(`templates.protocols.${kind}.${on ? 'enabled' : 'disabled'}`))
})

// Create: ask for a name, then show the new credential once.
const creating = ref<Kind | null>(null)
const newName = ref('')
const secret = ref<OnceSecret | null>(null)
function openCreate(kind: Kind) {
  creating.value = kind
  newName.value = ''
}
const create = useAction(async () => {
  const kind = creating.value
  if (!kind) return
  const name = newName.value.trim()
  if (kind === 'acme') {
    const res = await rpc('acme_eab_keys.create', { template_id: props.template.id, name })
    const directory = props.template.acme_directory_url ?? ''
    secret.value = {
      title: t('templates.protocols.acme.createdTitle', { name }),
      fields: [
        { label: t('templates.protocols.acme.kid'), value: res.data.kid },
        { label: t('templates.protocols.acme.hmac'), value: res.data.hmac_key },
      ],
      example: { label: t('templates.protocols.acme.example'), value: `certbot certonly --server ${directory} --eab-kid ${res.data.kid} --eab-hmac-key ${res.data.hmac_key} -d <name>` },
    }
    await refreshEab()
  } else {
    const res = await rpc('est_credentials.create', { template_id: props.template.id, name })
    const base = props.template.est_base_url ?? ''
    secret.value = {
      title: t('templates.protocols.est.createdTitle', { name }),
      fields: [
        { label: t('templates.protocols.est.username'), value: res.data.username },
        { label: t('templates.protocols.est.password'), value: res.data.password },
      ],
      example: { label: t('templates.protocols.est.example'), value: `curl --user ${res.data.username}:${res.data.password} -H 'Content-Type: application/pkcs10' --data-binary @request.b64 ${base.replace(/\/?$/, '/')}simpleenroll` },
    }
    await refreshEst()
  }
  creating.value = null
})

const revoking = ref<{ kind: Kind; credential: Credential } | null>(null)
const revoke = useAction(async () => {
  if (!revoking.value) return
  const { kind, credential } = revoking.value
  if (kind === 'acme') await rpc('acme_eab_keys.revoke', { id: credential.id })
  else await rpc('est_credentials.revoke', { id: credential.id })
  toast.success(t(`templates.protocols.${kind}.revoked`, { name: credential.name }))
  revoking.value = null
  await (kind === 'acme' ? refreshEab() : refreshEst())
})

const lastUsed = (credential: Credential) => (credential.last_used_at ? t('templates.protocols.lastUsed', { time: timeAgo(credential.last_used_at, locale.value) }) : t('templates.protocols.neverUsed'))
const enabled = (kind: Kind) => (kind === 'acme' ? props.template.allow_acme : props.template.allow_est)
const url = (kind: Kind) => (kind === 'acme' ? props.template.acme_directory_url : props.template.est_base_url)
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle>{{ t('templates.protocols.title') }}</CardTitle>
    </CardHeader>
    <CardContent class="flex flex-col gap-6">
      <section v-for="kind in (['acme', 'est'] as const)" :key="kind" class="flex flex-col gap-4">
        <div class="flex items-center gap-3">
          <Switch
            :id="`protocol-${kind}`"
            :model-value="enabled(kind)"
            :disabled="!canManage || toggle.busy"
            @update:model-value="(on: boolean) => toggle(kind, on)"
          />
          <Label :for="`protocol-${kind}`" class="font-medium">{{ t(`templates.protocols.${kind}.name`) }}</Label>
          <InfoTip :text="t(`templates.protocols.${kind}.hint`)" />
          <MetaChip v-if="kind === 'acme' && enabled('acme')" :label="t('templates.protocols.acme.accounts')" class="ml-auto">{{ template.acme_account_count }}</MetaChip>
        </div>

        <div v-if="enabled(kind)" class="flex flex-col gap-4 pl-11">
          <CaCopyField v-if="url(kind)" :label="t(`templates.protocols.${kind}.url`)" :value="url(kind)!" />

          <div class="flex flex-col gap-2">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs text-muted-foreground">{{ t(`templates.protocols.${kind}.credentials`) }}</span>
              <Button v-if="canManage" variant="outline" size="sm" @click="openCreate(kind)"><PlusIcon />{{ t(`templates.protocols.${kind}.new`) }}</Button>
            </div>
            <p v-if="!credentials(kind).length" class="rounded-md border border-dashed px-3 py-4 text-center text-sm text-muted-foreground">{{ t(`templates.protocols.${kind}.none`) }}</p>
            <ul v-else class="divide-y rounded-md border">
              <li v-for="credential in credentials(kind)" :key="credential.id" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
                <KeyRoundIcon class="size-4 shrink-0 text-muted-foreground" />
                <span class="min-w-32 flex-1 truncate font-medium" :class="{ 'text-muted-foreground line-through': credential.revoked_at }">{{ credential.name }}</span>
                <code class="truncate font-mono text-xs text-muted-foreground">{{ credential.handle }}</code>
                <Badge v-if="credential.revoked_at" variant="outline" class="text-muted-foreground">{{ t('templates.protocols.revokedBadge') }}</Badge>
                <span v-else class="text-xs text-muted-foreground">{{ lastUsed(credential) }}</span>
                <Button v-if="!credential.revoked_at && credential.can_revoke" variant="ghost" size="sm" class="h-7 text-destructive" @click="revoking = { kind, credential }">{{ t('templates.protocols.revoke') }}</Button>
              </li>
            </ul>
          </div>
        </div>
        <Separator v-if="kind === 'acme'" />
      </section>
    </CardContent>

    <Dialog :open="!!creating" @update:open="(open) => { if (!open) creating = null }">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ creating ? t(`templates.protocols.${creating}.new`) : '' }}</DialogTitle>
        </DialogHeader>
        <form class="flex flex-col gap-5" @submit.prevent="create()">
          <Field>
            <FieldLabel for="protocol-credential-name">{{ t('templates.protocols.credentialName') }}</FieldLabel>
            <Input id="protocol-credential-name" v-model="newName" maxlength="80" required autocomplete="off" :placeholder="t(`templates.protocols.${creating ?? 'acme'}.namePlaceholder`)" />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" @click="creating = null">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="create.busy" :disabled="!newName.trim()">{{ t('templates.protocols.create') }}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!revoking" @update:open="(open) => { if (!open) revoking = null }">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ revoking ? t(`templates.protocols.${revoking.kind}.revokeTitle`, { name: revoking.credential.name }) : '' }}</DialogTitle>
          <DialogDescription>{{ revoking ? t(`templates.protocols.${revoking.kind}.revokeText`) : '' }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" @click="revoking = null">{{ t('common.cancel') }}</Button>
          <Button variant="destructive" :loading="revoke.busy" @click="revoke()">{{ t('templates.protocols.revoke') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <OnceSecretDialog v-model="secret" />
  </Card>
</template>
