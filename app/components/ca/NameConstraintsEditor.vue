<script setup lang="ts">
import type { NameConstraintsInput } from '~/types/api'

/** Permitted and excluded DNS suffixes and IP ranges for a new CA. */
const model = defineModel<NameConstraintsInput>({ required: true })
const { t } = useI18n()

const set = (side: 'permitted' | 'excluded', kind: 'dns' | 'ip') =>
  computed({
    get: () => model.value[side][kind],
    set: (values: string[]) => (model.value = { ...model.value, [side]: { ...model.value[side], [kind]: values } }),
  })
const permittedDns = set('permitted', 'dns')
const permittedIp = set('permitted', 'ip')
const excludedDns = set('excluded', 'dns')
const excludedIp = set('excluded', 'ip')
</script>

<template>
  <div class="grid gap-6 md:grid-cols-2">
    <FieldSet class="gap-4">
      <FieldLegend variant="label">{{ t('cas.nc.permitted') }}</FieldLegend>
      <CaConstraintList id="nc-permitted-dns" v-model="permittedDns" kind="dns" :label="t('cas.nc.dns')" :info="t('cas.nc.dnsHint')" :placeholder="t('cas.nc.dnsPlaceholder')" />
      <CaConstraintList id="nc-permitted-ip" v-model="permittedIp" kind="ip" :label="t('cas.nc.ip')" :placeholder="t('cas.nc.ipPlaceholder')" />
    </FieldSet>
    <FieldSet class="gap-4">
      <FieldLegend variant="label">{{ t('cas.nc.excluded') }}</FieldLegend>
      <CaConstraintList id="nc-excluded-dns" v-model="excludedDns" kind="dns" :label="t('cas.nc.dns')" :info="t('cas.nc.dnsHint')" />
      <CaConstraintList id="nc-excluded-ip" v-model="excludedIp" kind="ip" :label="t('cas.nc.ip')" />
    </FieldSet>
  </div>
</template>
