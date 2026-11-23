<script setup lang="ts">
import type { CertificateAuthority } from '~/types/api'
import { TRAEFIK_CLIENT_AUTH_TYPES, TRAEFIK_NAME_INPUT_PATTERN, type TrustBundleFormState } from '~/utils/trustBundleForm'

/**
 * Name, slug (fixed after creation: it is part of the public URL), description, and the CAs,
 * picked from the CA tree. The chosen order is the order in the PEM. The Traefik card turns on the
 * Traefik configuration endpoint and says what it contains.
 */
const form = defineModel<TrustBundleFormState>({ required: true })
const props = defineProps<{ mode: 'create' | 'edit'; cas: CertificateAuthority[]; error?: string; errorCode?: string }>()
const { t } = useI18n()

const slugEdited = ref(false)
watch(
  () => form.value.name,
  (name) => {
    if (props.mode === 'create' && !slugEdited.value) form.value.slug = slugify(name)
  },
)

// CAs without a certificate have nothing to put into a bundle.
const rows = computed(() => caTree(props.cas.filter((ca) => ca.status !== 'pending_certificate')))
function toggle(id: string, checked: boolean | 'indeterminate') {
  const rest = form.value.ca_ids.filter((other) => other !== id)
  form.value.ca_ids = checked === true ? [...rest, id] : rest
}
const targetMissing = computed(() => props.errorCode === 'traefik_target_required')
const position = (id: string) => form.value.ca_ids.indexOf(id) + 1
</script>

<template>
  <div class="flex flex-col gap-6">
    <FormCard :title="t('trustBundles.form.bundle')">
      <FieldGroup>
        <Field>
          <FieldLabel for="bundle-name">{{ t('trustBundles.form.name') }}</FieldLabel>
          <Input id="bundle-name" v-model="form.name" maxlength="100" required :placeholder="t('trustBundles.form.namePlaceholder')" />
        </Field>
        <Field>
          <div class="flex items-center gap-1.5">
            <FieldLabel for="bundle-slug">{{ t('trustBundles.form.slug') }}</FieldLabel>
            <InfoTip :text="t('trustBundles.form.slugHint')" />
          </div>
          <Input
            id="bundle-slug"
            v-model="form.slug"
            maxlength="64"
            required
            :disabled="mode === 'edit'"
            pattern="[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?"
            class="font-mono"
            @input="slugEdited = true"
          />
        </Field>
        <Field>
          <FieldLabel for="bundle-description">{{ t('trustBundles.form.description') }}</FieldLabel>
          <Textarea id="bundle-description" v-model="form.description" rows="2" maxlength="1000" />
        </Field>
      </FieldGroup>
    </FormCard>

    <FormCard :title="t('trustBundles.form.cas')" :info="t('trustBundles.form.casHint')">
      <FieldGroup>
        <p v-if="!rows.length" class="text-sm text-muted-foreground">{{ t('trustBundles.form.noCas') }}</p>
        <ul v-else class="flex flex-col gap-2 rounded-md border p-3" :aria-label="t('trustBundles.form.cas')">
          <li v-for="row in rows" :key="row.key" :style="{ paddingLeft: `${row.depth * 1.25}rem` }">
            <Label v-if="row.kind === 'ca'" class="font-normal">
              <Checkbox :model-value="form.ca_ids.includes(row.ca.id)" @update:model-value="toggle(row.ca.id, $event)" />
              <span class="min-w-0 break-words">{{ row.ca.name }}</span>
              <CaStatusBadge v-if="row.ca.status !== 'active'" :status="row.ca.status" />
              <span v-if="position(row.ca.id)" class="text-xs text-muted-foreground tabular-nums">#{{ position(row.ca.id) }}</span>
            </Label>
            <span v-else class="font-mono text-xs break-all text-muted-foreground">{{ commonNameOf(row.subject) }}</span>
          </li>
        </ul>
        <Field orientation="horizontal">
          <Switch id="bundle-chain" v-model="form.include_chain" />
          <FieldContent>
            <div class="flex items-center gap-1.5">
              <FieldLabel for="bundle-chain">{{ t('trustBundles.form.includeChain') }}</FieldLabel>
              <InfoTip :text="t('trustBundles.form.includeChainHint')" />
            </div>
          </FieldContent>
        </Field>
      </FieldGroup>
    </FormCard>

    <Card>
      <CardHeader>
        <div class="flex min-w-0 items-center gap-2">
          <CardTitle>{{ t('trustBundles.form.traefik') }}</CardTitle>
          <InfoTip :text="t('trustBundles.form.traefikHint')" />
        </div>
        <CardAction>
          <Switch v-model="form.traefik_enabled" :aria-label="t('trustBundles.form.traefikEnabled')" />
        </CardAction>
      </CardHeader>
      <CardContent v-if="form.traefik_enabled">
        <FieldGroup>
          <Field orientation="horizontal" :data-invalid="targetMissing || undefined">
            <Switch id="bundle-traefik-client-auth" v-model="form.traefik_client_auth" :aria-invalid="targetMissing || undefined" />
            <FieldContent>
              <div class="flex items-center gap-1.5">
                <FieldLabel for="bundle-traefik-client-auth">{{ t('trustBundles.form.traefikClientAuth') }}</FieldLabel>
                <InfoTip :text="t('trustBundles.form.traefikClientAuthHint')" />
              </div>
            </FieldContent>
          </Field>
          <FieldGroup v-if="form.traefik_client_auth" class="pl-11">
            <Field :data-invalid="errorCode === 'invalid_traefik_tls_option_name' || undefined">
              <FieldLabel for="bundle-traefik-option">{{ t('trustBundles.form.traefikOptionName') }}</FieldLabel>
              <Input
                id="bundle-traefik-option"
                v-model="form.traefik_tls_option_name"
                maxlength="63"
                :pattern="TRAEFIK_NAME_INPUT_PATTERN"
                :placeholder="`${form.slug || 'slug'}-mtls`"
                :aria-invalid="errorCode === 'invalid_traefik_tls_option_name' || undefined"
                class="font-mono"
              />
            </Field>
            <Field>
              <FieldLabel for="bundle-traefik-auth-type">{{ t('trustBundles.form.traefikClientAuthType') }}</FieldLabel>
              <Select v-model="form.traefik_client_auth_type">
                <SelectTrigger id="bundle-traefik-auth-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="type in TRAEFIK_CLIENT_AUTH_TYPES" :key="type" :value="type">{{ t(`trustBundles.form.traefikAuthTypes.${type}`) }}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </FieldGroup>
          <Field orientation="horizontal" :data-invalid="targetMissing || undefined">
            <Switch id="bundle-traefik-transport" v-model="form.traefik_servers_transport" :aria-invalid="targetMissing || undefined" />
            <FieldContent>
              <div class="flex items-center gap-1.5">
                <FieldLabel for="bundle-traefik-transport">{{ t('trustBundles.form.traefikTransport') }}</FieldLabel>
                <InfoTip :text="t('trustBundles.form.traefikTransportHint')" />
              </div>
            </FieldContent>
          </Field>
          <FieldGroup v-if="form.traefik_servers_transport" class="pl-11">
            <Field :data-invalid="errorCode === 'invalid_traefik_servers_transport_name' || undefined">
              <FieldLabel for="bundle-traefik-transport-name">{{ t('trustBundles.form.traefikTransportName') }}</FieldLabel>
              <Input
                id="bundle-traefik-transport-name"
                v-model="form.traefik_servers_transport_name"
                maxlength="63"
                :pattern="TRAEFIK_NAME_INPUT_PATTERN"
                :placeholder="form.slug || 'slug'"
                :aria-invalid="errorCode === 'invalid_traefik_servers_transport_name' || undefined"
                class="font-mono"
              />
            </Field>
          </FieldGroup>
          <Field orientation="horizontal">
            <Switch id="bundle-traefik-token" v-model="form.traefik_require_token" />
            <FieldContent>
              <div class="flex items-center gap-1.5">
                <FieldLabel for="bundle-traefik-token">{{ t('trustBundles.form.traefikRequireToken') }}</FieldLabel>
                <InfoTip :text="t('trustBundles.form.traefikRequireTokenHint')" />
              </div>
            </FieldContent>
          </Field>
        </FieldGroup>
      </CardContent>
    </Card>

    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
  </div>
</template>
