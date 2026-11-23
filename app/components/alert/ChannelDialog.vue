<script setup lang="ts">
import { CopyIcon, TriangleAlertIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { AlertChannel } from '~/types/api'

/**
 * Create or edit an alert channel: email recipients or a webhook URL. A new webhook (or a
 * rotated secret) shows its signing secret once; it is cleared when the dialog closes.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ channel: AlertChannel | null }>()
const emit = defineEmits<{ saved: [channel: AlertChannel] }>()
const { t } = useI18n()
const rpc = useRpc()
const errorMessage = useErrorMessage()

const kind = ref<'email' | 'webhook'>('email')
const name = ref('')
const recipients = ref('')
const url = ref('')
const formError = ref('')
/** Shown once; the server never returns it again. */
const secret = ref<string | null>(null)

watch(open, (value) => {
  secret.value = null
  formError.value = ''
  if (!value) return
  kind.value = props.channel?.kind ?? 'email'
  name.value = props.channel?.name ?? ''
  recipients.value = props.channel?.recipients.join('\n') ?? ''
  url.value = props.channel?.url ?? ''
})

const recipientList = computed(() => recipients.value.split(/[\s,;]+/).map((r) => r.trim()).filter(Boolean))
const ready = computed(() => !!name.value.trim() && (kind.value === 'email' ? recipientList.value.length > 0 : /^https?:\/\/.+/i.test(url.value.trim())))

async function run(fn: () => Promise<{ data: { channel: AlertChannel; secret: string | null } }>) {
  formError.value = ''
  try {
    const res = await fn()
    emit('saved', res.data.channel)
    if (res.data.secret) secret.value = res.data.secret
    else {
      toast.success(t('alerts.channels.saved'))
      open.value = false
    }
  } catch (error) {
    if (!(error instanceof RpcError) || error.status !== 400) throw error
    formError.value = errorMessage(error)
  }
}

const submit = useAction(() =>
  run(() => {
    const base = { name: name.value.trim() }
    if (props.channel) {
      return rpc('alert_channels.update', { id: props.channel.id, ...base, ...(kind.value === 'email' ? { recipients: recipientList.value } : { url: url.value.trim() }) })
    }
    return kind.value === 'email'
      ? rpc('alert_channels.create', { kind: 'email', ...base, recipients: recipientList.value })
      : rpc('alert_channels.create', { kind: 'webhook', ...base, url: url.value.trim() })
  }),
)

const rotate = useAction(() => run(() => rpc('alert_channels.update', { id: props.channel!.id, rotate_secret: true })))

async function copySecret() {
  if (!secret.value) return
  await navigator.clipboard.writeText(secret.value)
  toast.success(t('common.copied'))
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-lg">
      <template v-if="secret">
        <DialogHeader>
          <DialogTitle>{{ t('alerts.channels.secretTitle') }}</DialogTitle>
          <DialogDescription>{{ t('alerts.channels.secretHint') }}</DialogDescription>
        </DialogHeader>
        <div class="flex gap-2">
          <Input :model-value="secret" readonly class="font-mono text-xs" :aria-label="t('alerts.channels.secretTitle')" @focus="($event.target as HTMLInputElement).select()" />
          <Button variant="outline" size="icon" class="shrink-0" :aria-label="t('common.copy')" @click="copySecret"><CopyIcon class="size-4" /></Button>
        </div>
        <p class="text-xs text-muted-foreground">{{ t('alerts.channels.signatureHint') }}</p>
        <DialogFooter>
          <Button @click="open = false">{{ t('common.done') }}</Button>
        </DialogFooter>
      </template>

      <template v-else>
        <DialogHeader>
          <DialogTitle>{{ channel ? t('alerts.channels.editTitle') : t('alerts.channels.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('alerts.channels.dialogDescription') }}</DialogDescription>
        </DialogHeader>
        <form class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
          <FieldGroup>
            <Field>
              <FieldLabel for="channel-kind">{{ t('alerts.channels.kind') }}</FieldLabel>
              <Select v-model="kind" :disabled="!!channel">
                <SelectTrigger id="channel-kind" class="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="email">{{ t('alerts.channels.kinds.email') }}</SelectItem>
                  <SelectItem value="webhook">{{ t('alerts.channels.kinds.webhook') }}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel for="channel-name">{{ t('alerts.channels.name') }}</FieldLabel>
              <Input id="channel-name" v-model="name" maxlength="100" required :placeholder="t('alerts.channels.namePlaceholder')" />
            </Field>
            <Field v-if="kind === 'email'">
              <FieldLabel for="channel-recipients">{{ t('alerts.channels.recipients') }}</FieldLabel>
              <Textarea id="channel-recipients" v-model="recipients" rows="3" spellcheck="false" placeholder="pki-team@example.com" />
              <FieldDescription>{{ t('alerts.channels.recipientsHint') }}</FieldDescription>
            </Field>
            <Field v-else>
              <FieldLabel for="channel-url">{{ t('alerts.channels.url') }}</FieldLabel>
              <Input id="channel-url" v-model="url" type="url" maxlength="2048" required spellcheck="false" class="font-mono text-xs" placeholder="https://hooks.example.internal/certifly" />
              <FieldDescription>{{ t('alerts.channels.urlHint') }}</FieldDescription>
            </Field>
            <Alert v-if="channel && channel.kind === 'webhook'">
              <TriangleAlertIcon />
              <AlertDescription class="flex flex-wrap items-center justify-between gap-2">
                <span>{{ t('alerts.channels.rotateHint') }}</span>
                <Button type="button" variant="outline" size="sm" :loading="rotate.busy" @click="rotate()">{{ t('alerts.channels.rotate') }}</Button>
              </AlertDescription>
            </Alert>
            <p v-if="formError" class="text-sm text-destructive">{{ formError }}</p>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
            <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ channel ? t('common.save') : t('alerts.channels.create') }}</Button>
          </DialogFooter>
        </form>
      </template>
    </DialogScrollContent>
  </Dialog>
</template>
