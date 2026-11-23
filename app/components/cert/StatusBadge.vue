<script setup lang="ts">
import type { CertificateStatus } from '~/types/api'

/** A certificate's status in its state colour: active green, expired red, revoked red, superseded grey. */
const props = defineProps<{ status: CertificateStatus }>()
const { t } = useI18n()

const tone = computed(
  () =>
    ({
      active: 'border-success/30 bg-success-soft text-success',
      expired: 'border-danger/30 bg-danger-soft text-danger',
      revoked: 'border-danger/30 bg-danger-soft text-danger',
      superseded: 'border-border bg-muted text-muted-foreground',
    })[props.status],
)
</script>

<template>
  <Badge variant="outline" :class="tone">{{ t(`certificates.status.${status}`) }}</Badge>
</template>
