<script setup lang="ts">
import { ArrowLeftIcon, GlobeIcon, InfoIcon, LandmarkIcon, NetworkIcon, TriangleAlertIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CaSigning, CertificateAuthority, DnAttributeType, KeyAlgorithm, NameConstraintsInput, RpcInput } from '~/types/api'

/**
 * Create a CA in two steps: pick the kind (root, intermediate signed here, or externally
 * signed), then fill in its subject, key, validity, path length and name constraints.
 */
definePageMeta({ titleKey: 'cas.new.title', requires: ['instance', 'create_certificate_authority'] })

const { t, d } = useI18n()
const rpc = useRpc()
const router = useRouter()

useHead({ title: () => t('cas.new.title') })

const DAY_MS = 24 * 60 * 60 * 1000
const ALGORITHMS: KeyAlgorithm[] = ['ecdsa-p384', 'ecdsa-p256', 'rsa-4096', 'rsa-3072', 'rsa-2048']
const PATH_LENGTHS = ['unlimited', '0', '1', '2', '3', '4'] as const
const KINDS = [
  { value: 'self_signed', icon: LandmarkIcon },
  { value: 'internal', icon: NetworkIcon },
  { value: 'external', icon: GlobeIcon },
] as const satisfies readonly { value: CaSigning; icon: unknown }[]

const kind = ref<CaSigning | null>(null)

// Parents: active CAs that may still sign a CA below them.
const { data: parents } = await useAsyncData(
  'ca-parents',
  async () => (await rpc('certificate_authorities.list', { limit: 200 })).data.filter((ca) => ca.status === 'active' && ca.max_path_length !== 0),
  { default: () => [] as CertificateAuthority[] },
)

const emptyConstraints = (): NameConstraintsInput => ({ permitted: { dns: [], ip: [], email: [] }, excluded: { dns: [], ip: [], email: [] } })
const form = reactive({
  parent_ca_id: '',
  name: '',
  slug: '',
  description: '',
  subject: { CN: '', O: '', OU: '', C: '', ST: '', L: '' } as Record<'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L', string>,
  key_algorithm: 'ecdsa-p384' as KeyAlgorithm,
  validity_days: 3650,
  path_length: 'unlimited' as (typeof PATH_LENGTHS)[number],
  name_constraints: emptyConstraints(),
})

const parent = computed(() => parents.value.find((p) => p.id === form.parent_ca_id) ?? null)
const parentDaysLeft = computed(() => (parent.value?.not_after ? Math.floor((new Date(parent.value.not_after).getTime() - Date.now()) / DAY_MS) - 1 : null))

/** Defaults that suit each kind: a long-lived unlimited root, a short issuing intermediate. */
function choose(value: CaSigning) {
  kind.value = value
  form.path_length = value === 'self_signed' ? 'unlimited' : value === 'internal' ? '0' : '1'
  form.validity_days = value === 'self_signed' ? 3650 : 1825
  form.name_constraints = emptyConstraints()
}

watch(parent, (value) => {
  if (value && parentDaysLeft.value !== null) form.validity_days = Math.max(1, Math.min(1825, parentDaysLeft.value))
})

// The slug follows the name until someone edits it.
const slugEdited = ref(false)
watch(
  () => form.name,
  (name) => {
    if (!slugEdited.value) form.slug = slugify(name)
  },
)

const needsConstraints = computed(() => kind.value !== 'self_signed')
const hasPermitted = computed(() => form.name_constraints.permitted.dns.length + form.name_constraints.permitted.ip.length > 0)
const ready = computed(
  () =>
    !!kind.value &&
    !!form.name.trim() &&
    /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(form.slug) &&
    !!form.subject.CN.trim() &&
    (kind.value !== 'internal' || !!form.parent_ca_id) &&
    (!needsConstraints.value || hasPermitted.value) &&
    (kind.value === 'external' || form.validity_days >= 1),
)

const submit = useAction(async () => {
  const subject = (Object.entries(form.subject) as [DnAttributeType, string][]).filter(([, value]) => value.trim()).map(([type, value]) => ({ type, value: value.trim() }))
  const nc = form.name_constraints
  const isEmpty = !nc.permitted.dns.length && !nc.permitted.ip.length && !nc.excluded.dns.length && !nc.excluded.ip.length
  const common = {
    name: form.name.trim(),
    slug: form.slug,
    description: form.description.trim() || undefined,
    subject,
    key_algorithm: form.key_algorithm,
    path_length: form.path_length === 'unlimited' ? null : Number(form.path_length),
    name_constraints: isEmpty ? null : nc,
  }
  const body: RpcInput['certificate_authorities.create'] =
    kind.value === 'external'
      ? { ...common, signing: 'external' }
      : kind.value === 'internal'
        ? { ...common, signing: 'internal', parent_ca_id: form.parent_ca_id, validity_days: form.validity_days }
        : { ...common, signing: 'self_signed', validity_days: form.validity_days }
  const res = await rpc('certificate_authorities.create', body)
  toast.success(t('cas.new.created', { name: res.data.name }))
  await router.push(`/certificate-authorities/${res.data.id}`)
})
</script>

<template>
  <div class="mx-auto flex w-full max-w-3xl flex-col gap-8 p-4 md:p-10">
    <section v-if="!kind" class="flex flex-col gap-4">
      <h2 class="text-lg font-semibold tracking-tight">{{ t('cas.new.chooseKind') }}</h2>
      <div class="grid gap-3 sm:grid-cols-3">
        <button
          v-for="option in KINDS"
          :key="option.value"
          type="button"
          class="flex flex-col items-start gap-2 rounded-lg border p-4 text-left transition-colors hover:bg-accent/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
          @click="choose(option.value)"
        >
          <component :is="option.icon" class="size-5 text-primary" />
          <span class="font-medium">{{ t(`cas.new.kinds.${option.value}.title`) }}</span>
          <span class="text-sm text-muted-foreground">{{ t(`cas.new.kinds.${option.value}.description`) }}</span>
        </button>
      </div>
    </section>

    <form v-else class="flex flex-col gap-6" @submit.prevent="submit()">
      <div class="flex flex-wrap items-center gap-3">
        <Button type="button" variant="ghost" size="sm" @click="kind = null"><ArrowLeftIcon />{{ t('common.back') }}</Button>
        <h2 class="text-lg font-semibold tracking-tight">{{ t(`cas.new.kinds.${kind}.title`) }}</h2>
      </div>

      <Alert v-if="kind === 'self_signed'" class="border-warning/40 bg-warning-soft text-warning">
        <TriangleAlertIcon />
        <AlertTitle>{{ t('cas.new.rootWarningTitle') }}</AlertTitle>
        <AlertDescription class="text-foreground">{{ t('cas.new.rootWarning') }}</AlertDescription>
      </Alert>
      <Alert v-else-if="kind === 'external'">
        <InfoIcon />
        <AlertDescription>{{ t('cas.new.validityExternal') }}</AlertDescription>
      </Alert>

      <FormCard :step="1" :title="t('cas.new.identity')">
        <FieldGroup>
          <Field v-if="kind === 'internal'">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="ca-parent">{{ t('cas.new.parent') }}</FieldLabel>
              <InfoTip v-if="parent?.not_after" :text="t('cas.new.parentHint', { date: d(new Date(parent.not_after), { dateStyle: 'medium' }) })" />
            </div>
            <p v-if="!parents.length" class="text-sm text-muted-foreground">{{ t('cas.new.noParents') }}</p>
            <Select v-else v-model="form.parent_ca_id">
              <SelectTrigger id="ca-parent" class="w-full"><SelectValue :placeholder="t('cas.new.parentPlaceholder')" /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="option in parents" :key="option.id" :value="option.id">{{ option.name }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel for="ca-name">{{ t('cas.new.name') }}</FieldLabel>
            <Input id="ca-name" v-model="form.name" maxlength="100" required :placeholder="t('cas.new.namePlaceholder')" />
          </Field>
          <Field>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="ca-slug">{{ t('cas.new.slug') }}</FieldLabel>
              <InfoTip :text="t('cas.new.slugHint')" />
            </div>
            <Input id="ca-slug" v-model="form.slug" maxlength="64" required pattern="[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?" class="font-mono" @input="slugEdited = true" />
          </Field>
          <Field>
            <FieldLabel for="ca-description">{{ t('cas.new.descriptionLabel') }}</FieldLabel>
            <Textarea id="ca-description" v-model="form.description" rows="2" maxlength="1000" :placeholder="t('cas.new.descriptionPlaceholder')" />
          </Field>
        </FieldGroup>
      </FormCard>

      <FormCard :step="2" :title="t('cas.new.subject')">
        <FieldGroup class="grid gap-4 sm:grid-cols-2">
          <Field class="sm:col-span-2">
            <FieldLabel for="ca-cn">{{ t('cas.new.commonName') }}</FieldLabel>
            <Input id="ca-cn" v-model="form.subject.CN" maxlength="256" required />
          </Field>
          <Field>
            <FieldLabel for="ca-o">{{ t('cas.new.organization') }}</FieldLabel>
            <Input id="ca-o" v-model="form.subject.O" maxlength="256" />
          </Field>
          <Field>
            <FieldLabel for="ca-ou">{{ t('cas.new.organizationalUnit') }}</FieldLabel>
            <Input id="ca-ou" v-model="form.subject.OU" maxlength="256" />
          </Field>
          <Field>
            <FieldLabel for="ca-c">{{ t('cas.new.country') }}</FieldLabel>
            <Input id="ca-c" v-model="form.subject.C" maxlength="2" pattern="[A-Z]{2}" :placeholder="t('cas.new.countryHint')" />
          </Field>
          <Field>
            <FieldLabel for="ca-st">{{ t('cas.new.state') }}</FieldLabel>
            <Input id="ca-st" v-model="form.subject.ST" maxlength="256" />
          </Field>
          <Field>
            <FieldLabel for="ca-l">{{ t('cas.new.locality') }}</FieldLabel>
            <Input id="ca-l" v-model="form.subject.L" maxlength="256" />
          </Field>
        </FieldGroup>
      </FormCard>

      <FormCard :step="3" :title="t('cas.new.key')">
        <FieldGroup class="grid gap-4 sm:grid-cols-2">
          <Field>
            <FieldLabel for="ca-algorithm">{{ t('cas.new.algorithm') }}</FieldLabel>
            <Select v-model="form.key_algorithm">
              <SelectTrigger id="ca-algorithm" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="algorithm in ALGORITHMS" :key="algorithm" :value="algorithm">{{ algorithm === 'ecdsa-p384' ? `${t(`cas.algorithms.${algorithm}`)} ${t('cas.recommended')}` : t(`cas.algorithms.${algorithm}`) }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="ca-path">{{ t('cas.pathLength') }}</FieldLabel>
              <InfoTip :text="t('cas.pathLengthHint')" />
            </div>
            <Select v-model="form.path_length">
              <SelectTrigger id="ca-path" class="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="value in PATH_LENGTHS" :key="value" :value="value">{{ value === 'unlimited' ? t('cas.pathLengthUnlimited') : value }}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field v-if="kind !== 'external'" class="sm:col-span-2">
            <div class="flex items-center gap-1.5">
              <FieldLabel for="ca-validity">{{ t('cas.new.validity') }}</FieldLabel>
              <InfoTip :text="t('cas.new.validityHint', { years: (form.validity_days / 365).toFixed(1) })" />
            </div>
            <Input id="ca-validity" v-model.number="form.validity_days" type="number" min="1" :max="parentDaysLeft ?? 36500" required class="sm:max-w-48" />
          </Field>
        </FieldGroup>
      </FormCard>

      <FormCard :step="4" :title="t('cas.new.constraints')" :info="t(`cas.new.constraintsHint.${kind}`)">
        <CaNameConstraintsEditor v-model="form.name_constraints" />
      </FormCard>

      <div class="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="outline" as-child><NuxtLink to="/certificate-authorities">{{ t('common.cancel') }}</NuxtLink></Button>
        <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ kind === 'external' ? t('cas.new.submitExternal') : t('cas.new.submit') }}</Button>
      </div>
    </form>
  </div>
</template>
