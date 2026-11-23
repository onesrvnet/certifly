<script setup lang="ts">
import type { SshCa } from '~/types/api'

/**
 * Everything a host group sets, in three cards: general (name, slug, CA, host names), user
 * certificates (lifetimes, key policy, options) and host certificates (lifetime). Messages for
 * fields the server refused show next to those fields.
 */
const form = defineModel<HostGroupFormState>({ required: true })
const props = defineProps<{
  cas: SshCa[]
  mode: 'create' | 'edit'
  errors?: Partial<Record<HostGroupField, string>>
  problems?: string[]
  disabled?: boolean
}>()
const { t } = useI18n()

const error = (field: HostGroupField) => props.errors?.[field]

// The slug follows the name on create until someone edits it.
const slugEdited = ref(false)
watch(
  () => form.value.name,
  (name) => {
    if (props.mode === 'create' && !slugEdited.value) form.value.slug = slugify(name)
  },
)

const FORWARDING = [
  { value: 'permit-pty', label: 'ssh.extensions.pty' },
  { value: 'permit-port-forwarding', label: 'ssh.extensions.port' },
  { value: 'permit-X11-forwarding', label: 'ssh.extensions.x11' },
  { value: 'permit-agent-forwarding', label: 'ssh.extensions.agent' },
] as const
const setExtension = (value: string, on: boolean | 'indeterminate') => {
  const rest = form.value.user_extensions.filter((e) => e !== value)
  form.value.user_extensions = on === true ? [...rest, value].sort() : rest
}

const PATTERN = /^(\*\*?\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/
const checkPattern = (value: string) => (PATTERN.test(value) ? null : t('sshHostGroups.form.invalidPattern'))
const checkAddress = (value: string) => (/^[0-9a-f:.]+(\/\d{1,3})?$/i.test(value) ? null : t('sshHostGroups.form.invalidAddress'))

const ttlError = computed(() => error('ttl') ?? (form.value.user_ttl_default_hours > form.value.user_ttl_max_hours ? t('sshHostGroups.form.defaultAboveMax') : undefined))
</script>

<template>
  <div class="flex flex-col gap-6">
    <FormCard :title="t('sshHostGroups.form.sections.general')">
      <FieldGroup>
        <Field>
          <FieldLabel for="hg-name">{{ t('sshHostGroups.form.name') }}</FieldLabel>
          <Input id="hg-name" v-model="form.name" maxlength="100" required :disabled="disabled" :placeholder="t('sshHostGroups.form.namePlaceholder')" />
        </Field>
        <Field :data-invalid="!!error('slug') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel for="hg-slug">{{ t('sshHostGroups.form.slug') }}</FieldLabel>
            <InfoTip :text="t('sshHostGroups.form.slugTip')" />
          </div>
          <Input id="hg-slug" v-model="form.slug" maxlength="64" required :disabled="disabled || mode === 'edit'" pattern="[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?" class="font-mono" @input="slugEdited = true" />
          <FieldError v-if="error('slug')">{{ error('slug') }}</FieldError>
        </Field>
        <Field :data-invalid="!!error('ssh_ca_id') || undefined">
          <FieldLabel for="hg-ca">{{ t('sshHostGroups.form.ca') }}</FieldLabel>
          <p v-if="!cas.length" class="text-sm text-muted-foreground">{{ t('sshHostGroups.form.noCas') }}</p>
          <Select v-else v-model="form.ssh_ca_id" :disabled="disabled || mode === 'edit'">
            <SelectTrigger id="hg-ca" class="w-full"><SelectValue :placeholder="t('sshHostGroups.form.caPlaceholder')" /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="ca in cas" :key="ca.id" :value="ca.id">{{ ca.name }}</SelectItem>
            </SelectContent>
          </Select>
          <FieldError v-if="error('ssh_ca_id')">{{ error('ssh_ca_id') }}</FieldError>
        </Field>
        <ChipInput
          id="hg-patterns"
          v-model="form.host_patterns"
          :label="t('sshHostGroups.form.hostNames')"
          :info="t('sshHostGroups.form.hostNamesTip')"
          :placeholder="t('sshHostGroups.form.hostNamesPlaceholder')"
          :error="error('host_patterns')"
          :problems="problems"
          :check="checkPattern"
          :disabled="disabled"
          lowercase
          mono
        />
      </FieldGroup>
    </FormCard>

    <FormCard :title="t('sshHostGroups.form.sections.user')">
      <FieldGroup>
        <div class="grid gap-4 sm:grid-cols-2">
          <Field :data-invalid="!!ttlError || undefined">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="hg-ttl-default">{{ t('sshHostGroups.form.ttlDefault') }}</FieldLabel>
              <InfoTip :text="t('sshHostGroups.form.ttlTip')" />
            </div>
            <div class="flex items-center gap-2">
              <Input id="hg-ttl-default" v-model.number="form.user_ttl_default_hours" type="number" min="0.1" :max="SSH_USER_TTL_MAX_HOURS" step="any" required :disabled="disabled" class="w-28" />
              <span class="text-sm text-muted-foreground">{{ t('ssh.units.hours') }}</span>
            </div>
          </Field>
          <Field :data-invalid="!!ttlError || undefined">
            <FieldLabel for="hg-ttl-max">{{ t('sshHostGroups.form.ttlMax') }}</FieldLabel>
            <div class="flex items-center gap-2">
              <Input id="hg-ttl-max" v-model.number="form.user_ttl_max_hours" type="number" min="0.1" :max="SSH_USER_TTL_MAX_HOURS" step="any" required :disabled="disabled" class="w-28" />
              <span class="text-sm text-muted-foreground">{{ t('ssh.units.hours') }}</span>
            </div>
          </Field>
        </div>
        <FieldError v-if="ttlError" class="-mt-2">{{ ttlError }}</FieldError>

        <Field>
          <div class="flex items-center gap-1.5">
            <FieldLabel>{{ t('sshHostGroups.form.keyPolicy') }}</FieldLabel>
            <InfoTip :text="t('sshHostGroups.form.keyPolicyTip')" />
          </div>
          <RadioGroup v-model="form.key_policy" :disabled="disabled" class="gap-2">
            <Label v-for="policy in SSH_KEY_POLICIES" :key="policy" :for="`hg-key-${policy}`" class="font-normal">
              <RadioGroupItem :id="`hg-key-${policy}`" :value="policy" />
              {{ t(`ssh.keyPolicy.option.${policy}`) }}
            </Label>
          </RadioGroup>
        </Field>

        <Field>
          <FieldLabel>{{ t('sshHostGroups.form.allow') }}</FieldLabel>
          <div class="grid gap-2 sm:grid-cols-2">
            <Label v-for="option in FORWARDING" :key="option.value" class="font-normal">
              <Checkbox :model-value="form.user_extensions.includes(option.value)" :disabled="disabled" @update:model-value="setExtension(option.value, $event)" />
              {{ t(option.label) }}
            </Label>
          </div>
        </Field>

        <Field :data-invalid="!!error('force_command') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel for="hg-command">{{ t('sshHostGroups.form.forceCommand') }}</FieldLabel>
            <InfoTip :text="t('sshHostGroups.form.forceCommandTip')" />
          </div>
          <Input id="hg-command" v-model="form.force_command" maxlength="1024" :disabled="disabled" class="font-mono" autocomplete="off" spellcheck="false" />
          <FieldError v-if="error('force_command')">{{ error('force_command') }}</FieldError>
        </Field>

        <ChipInput
          id="hg-source"
          v-model="form.source_address"
          :label="t('sshHostGroups.form.sourceAddress')"
          :info="t('sshHostGroups.form.sourceAddressTip')"
          :placeholder="t('sshHostGroups.form.sourceAddressPlaceholder')"
          :error="error('source_address')"
          :check="checkAddress"
          :disabled="disabled"
          mono
        />
      </FieldGroup>
    </FormCard>

    <FormCard :title="t('sshHostGroups.form.sections.host')">
      <FieldGroup>
        <Field :data-invalid="!!error('host_ttl') || undefined">
          <div class="flex items-center gap-1.5">
            <FieldLabel for="hg-host-ttl">{{ t('sshHostGroups.form.hostTtl') }}</FieldLabel>
            <InfoTip :text="t('sshHostGroups.form.hostTtlTip')" />
          </div>
          <div class="flex items-center gap-2">
            <Input id="hg-host-ttl" v-model.number="form.host_ttl_days" type="number" min="0.042" max="365" step="any" required :disabled="disabled" class="w-28" />
            <span class="text-sm text-muted-foreground">{{ t('ssh.units.days') }}</span>
          </div>
          <FieldError v-if="error('host_ttl')">{{ error('host_ttl') }}</FieldError>
        </Field>
      </FieldGroup>
    </FormCard>
  </div>
</template>
