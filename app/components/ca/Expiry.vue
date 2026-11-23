<script setup lang="ts">
/**
 * "Valid until 3 Mar 2036 (expires in 9 years)", the relative part turning amber in the last
 * 30 days and red once it has passed.
 */
/** `relative` shows only the "(expires in …)" part, next to a date shown elsewhere. */
const props = defineProps<{ notAfter: string | null; relative?: boolean }>()
const { t, d, locale } = useI18n()

const SOON_MS = 30 * 24 * 60 * 60 * 1000
const state = computed(() => {
  if (!props.notAfter) return null
  const left = new Date(props.notAfter).getTime() - Date.now()
  return left <= 0 ? 'expired' : left < SOON_MS ? 'soon' : 'ok'
})
</script>

<template>
  <span v-if="notAfter" class="text-xs text-muted-foreground">
    <template v-if="!relative"><time :datetime="notAfter" :title="notAfter">{{ t('cas.validUntil', { date: d(new Date(notAfter), { dateStyle: 'medium' }) }) }}</time> </template>
    (<span :class="{ 'text-warning': state === 'soon', 'text-danger': state === 'expired' }">{{ state === 'expired' ? t('cas.expiredAgo', { time: timeAgo(notAfter, locale) }) : t('cas.expiresIn', { time: timeAgo(notAfter, locale) }) }}</span>)
  </span>
</template>
