<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { AlertChannel, AlertEventName, AlertRule, CertificateAuthority, Template } from '~/types/api'

/**
 * Create or edit an alert rule: what event, which certificates or CAs (none picked means all),
 * the warning thresholds for expiry events, and the channels it sends to.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ rule: AlertRule | null; channels: AlertChannel[]; cas: CertificateAuthority[]; templates: Template[] }>()
const emit = defineEmits<{ saved: [rule: AlertRule] }>()
const { t } = useI18n()
const rpc = useRpc()
const errorMessage = useErrorMessage()

const EVENTS: AlertEventName[] = ['expiring', 'ca_expiring', 'ssh_host_expiring', 'issued', 'revoked', 'crl_failed']
const name = ref('')
const event = ref<AlertEventName>('expiring')
const days = ref('30, 7, 1')
const caIds = ref<string[]>([])
const templateIds = ref<string[]>([])
const includeImported = ref(false)
const channelIds = ref<string[]>([])
const enabled = ref(true)
const formError = ref('')

watch(open, (value) => {
  formError.value = ''
  if (!value) return
  const rule = props.rule
  name.value = rule?.name ?? ''
  event.value = rule?.event ?? 'expiring'
  days.value = rule?.days_before.length ? rule.days_before.join(', ') : '30, 7, 1'
  caIds.value = [...(rule?.ca_ids ?? [])]
  templateIds.value = [...(rule?.template_ids ?? [])]
  includeImported.value = rule?.include_imported ?? false
  channelIds.value = [...(rule?.channel_ids ?? [])]
  enabled.value = rule?.enabled ?? true
})

const expiry = computed(() => event.value === 'expiring' || event.value === 'ca_expiring' || event.value === 'ssh_host_expiring')
const aboutCertificates = computed(() => event.value === 'expiring' || event.value === 'issued' || event.value === 'revoked')
const thresholds = computed(() => days.value.split(/[\s,;]+/).filter(Boolean).map(Number))
const thresholdsValid = computed(() => !expiry.value || (thresholds.value.length > 0 && thresholds.value.every((n) => Number.isInteger(n) && n >= 1 && n <= 3650)))
const ready = computed(() => !!name.value.trim() && channelIds.value.length > 0 && thresholdsValid.value)

const lists = { channels: channelIds, cas: caIds, templates: templateIds }
function toggle(which: keyof typeof lists, id: string, checked: boolean | 'indeterminate') {
  const list = lists[which]
  list.value = checked === true ? [...new Set([...list.value, id])] : list.value.filter((other) => other !== id)
}

const submit = useAction(async () => {
  formError.value = ''
  const body = {
    name: name.value.trim(),
    event: event.value,
    ca_ids: event.value === 'ssh_host_expiring' ? [] : caIds.value,
    template_ids: aboutCertificates.value ? templateIds.value : [],
    include_imported: event.value === 'expiring' ? includeImported.value : false,
    days_before: expiry.value ? thresholds.value : [],
    channel_ids: channelIds.value,
    enabled: enabled.value,
  }
  try {
    const res = props.rule ? await rpc('alert_rules.update', { id: props.rule.id, ...body }) : await rpc('alert_rules.create', body)
    toast.success(t('alerts.rules.saved'))
    open.value = false
    emit('saved', res.data)
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 404)) throw error
    formError.value = errorMessage(error)
  }
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ rule ? t('alerts.rules.editTitle') : t('alerts.rules.createTitle') }}</DialogTitle>
        <DialogDescription>{{ t('alerts.rules.dialogDescription') }}</DialogDescription>
      </DialogHeader>
      <form class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
        <FieldGroup>
          <Field>
            <FieldLabel for="rule-name">{{ t('alerts.rules.name') }}</FieldLabel>
            <Input id="rule-name" v-model="name" maxlength="100" required :placeholder="t('alerts.rules.namePlaceholder')" />
          </Field>
          <Field>
            <FieldLabel for="rule-event">{{ t('alerts.rules.event') }}</FieldLabel>
            <Select v-model="event">
              <SelectTrigger id="rule-event" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="value in EVENTS" :key="value" :value="value">{{ t(`alerts.events.${value}`) }}</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>{{ t(`alerts.eventHints.${event}`) }}</FieldDescription>
          </Field>
          <Field v-if="expiry" :data-invalid="!thresholdsValid || undefined">
            <FieldLabel for="rule-days">{{ t('alerts.rules.daysBefore') }}</FieldLabel>
            <Input id="rule-days" v-model="days" inputmode="numeric" placeholder="30, 7, 1" />
            <FieldDescription>{{ t('alerts.rules.daysBeforeHint') }}</FieldDescription>
          </Field>
          <FieldSet>
            <FieldLegend variant="label">{{ t('alerts.rules.channels') }}</FieldLegend>
            <p v-if="!channels.length" class="text-sm text-muted-foreground">{{ t('alerts.rules.noChannels') }}</p>
            <div v-else class="flex flex-col gap-2">
              <Label v-for="channel in channels" :key="channel.id" class="font-normal">
                <Checkbox :model-value="channelIds.includes(channel.id)" @update:model-value="toggle('channels', channel.id, $event)" />
                <span class="min-w-0 break-words">{{ channel.name }}</span>
                <span class="text-xs text-muted-foreground">{{ t(`alerts.channels.kinds.${channel.kind}`) }}</span>
              </Label>
            </div>
          </FieldSet>
          <FieldSet v-if="event !== 'ssh_host_expiring'">
            <FieldLegend variant="label">{{ t('alerts.rules.cas') }}</FieldLegend>
            <FieldDescription>{{ t('alerts.rules.noneMeansAll') }}</FieldDescription>
            <div class="flex max-h-40 flex-col gap-2 overflow-y-auto">
              <Label v-for="ca in cas" :key="ca.id" class="font-normal">
                <Checkbox :model-value="caIds.includes(ca.id)" @update:model-value="toggle('cas', ca.id, $event)" />
                <span class="min-w-0 break-words">{{ ca.name }}</span>
              </Label>
            </div>
          </FieldSet>
          <FieldSet v-if="aboutCertificates && templates.length">
            <FieldLegend variant="label">{{ t('alerts.rules.templates') }}</FieldLegend>
            <FieldDescription>{{ t('alerts.rules.noneMeansAll') }}</FieldDescription>
            <div class="flex max-h-40 flex-col gap-2 overflow-y-auto">
              <Label v-for="template in templates" :key="template.id" class="font-normal">
                <Checkbox :model-value="templateIds.includes(template.id)" @update:model-value="toggle('templates', template.id, $event)" />
                <span class="min-w-0 break-words">{{ template.name }}</span>
              </Label>
            </div>
          </FieldSet>
          <Field v-if="event === 'expiring'" orientation="horizontal">
            <Switch id="rule-imported" v-model="includeImported" />
            <FieldContent>
              <FieldLabel for="rule-imported">{{ t('alerts.rules.includeImported') }}</FieldLabel>
              <FieldDescription>{{ t('alerts.rules.includeImportedHint') }}</FieldDescription>
            </FieldContent>
          </Field>
          <Field orientation="horizontal">
            <Switch id="rule-enabled" v-model="enabled" />
            <FieldLabel for="rule-enabled">{{ t('alerts.rules.enabled') }}</FieldLabel>
          </Field>
          <p v-if="formError" class="text-sm text-destructive">{{ formError }}</p>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ rule ? t('common.save') : t('alerts.rules.create') }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
