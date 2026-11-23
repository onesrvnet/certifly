<script setup lang="ts">
import type { CaStatus } from '~/types/api'

/**
 * A CA's status in its state colour: active green, pending blue, expired and revoked red,
 * disabled grey. A revoked CA is also disabled; revoked says more, so it wins.
 */
const props = defineProps<{ status: CaStatus; revoked?: boolean }>()
const { t } = useI18n()

const tone = computed(() =>
  props.revoked
    ? 'border-danger/30 bg-danger-soft text-danger'
    : ({
      active: 'border-success/30 bg-success-soft text-success',
      pending_certificate: 'border-info/30 bg-info-soft text-info',
      expired: 'border-danger/30 bg-danger-soft text-danger',
      disabled: 'border-border bg-muted text-muted-foreground',
    })[props.status],
)
</script>

<template>
  <Badge variant="outline" :class="tone">{{ revoked ? t('cas.status.revoked') : t(`cas.status.${status}`) }}</Badge>
</template>
