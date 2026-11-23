<script setup lang="ts">
import type { NuxtError } from '#app'

/**
 * Error page. Missing or inaccessible content shows inside the app shell when signed in,
 * so the sidebar stays usable; app errors and being offline get a page of their own,
 * since the shell itself may be what failed.
 */
const props = defineProps<{ error: NuxtError }>()

const { t } = useI18n()
const auth = useAuthStore()

/** `data` arrives as a JSON string after server rendering. */
const data = computed<{ title?: string; errorId?: string; offline?: boolean }>(() => {
  const raw = props.error.data
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw)
    } catch {
      return {}
    }
  }
  return (raw as object | undefined) ?? {}
})

const kind = computed(() => {
  if (data.value.offline) return 'offline'
  if (props.error.statusCode === 404) return 'notFound'
  if (props.error.statusCode === 403) return 'forbidden'
  return 'server'
})
const code = computed(() => (kind.value === 'offline' ? '' : String(props.error.statusCode || 500)))
const title = computed(() => data.value.title ?? t(`errorPage.${kind.value}Title`))
const inShell = computed(() => (kind.value === 'notFound' || kind.value === 'forbidden') && !!auth.user)

// High priority: the app layout sets its own (page) title after this.
useHead({ title }, { tagPriority: 'high' })

const goHome = () => clearError({ redirect: '/' })
const tryAgain = () => (import.meta.client ? window.location.reload() : undefined)

const copied = ref(false)
async function copyId() {
  if (!data.value.errorId) return
  await navigator.clipboard.writeText(data.value.errorId)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}
</script>

<template>
  <NuxtLayout :name="inShell ? 'default' : false">
    <div class="flex min-h-[calc(100svh-3.5rem)] items-center justify-center bg-background px-6 py-16" :class="!inShell && 'min-h-svh'">
      <div class="flex max-w-md flex-col items-center gap-4 text-center">
        <span v-if="!inShell" class="mb-6 h-7"><AppLogo /></span>
        <p v-if="code" class="error-code select-none text-[7rem] leading-none font-bold tracking-tight md:text-[9rem]" aria-hidden="true">{{ code }}</p>
        <h1 class="text-2xl font-semibold tracking-tight">{{ title }}</h1>
        <p class="text-muted-foreground">{{ t(`errorPage.${kind}Text`) }}</p>
        <div class="mt-2 flex flex-wrap justify-center gap-2">
          <Button v-if="kind === 'server' || kind === 'offline'" @click="tryAgain">{{ t('errorPage.tryAgain') }}</Button>
          <Button v-if="kind !== 'offline'" :variant="kind === 'server' ? 'outline' : 'default'" @click="goHome">{{ t('errorPage.goHome') }}</Button>
        </div>
        <button
          v-if="kind === 'server' && data.errorId"
          type="button"
          class="mt-2 text-xs text-muted-foreground hover:text-foreground"
          :title="t('errorPage.copyId')"
          @click="copyId"
        >
          {{ copied ? t('errorPage.copied') : t('errorPage.errorId', { id: data.errorId }) }}
        </button>
      </div>
    </div>
  </NuxtLayout>
</template>

<style scoped>
/* Large outlined status code in the brand colour. */
.error-code {
  color: transparent;
  -webkit-text-stroke: 2px var(--primary);
  background: linear-gradient(180deg, var(--brand-soft), transparent 80%);
  -webkit-background-clip: text;
  background-clip: text;
}
</style>
