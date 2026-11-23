<script setup lang="ts">
import { KeyRoundIcon } from '@lucide/vue'

/**
 * "Continue with <provider>" button for the configured OpenID Connect provider. It is a full
 * page load to the start URL; the flow comes back to /login?error=… if it fails. A setup token
 * is passed along for the first sign-in on an empty instance. `separator` adds an "or" line below.
 */
defineProps<{ name: string; setupToken?: string; separator?: boolean }>()

const { t } = useI18n()
</script>

<template>
  <div class="flex flex-col gap-2">
    <Button variant="outline" as-child>
      <a :href="setupToken ? `/auth/oidc?setup_token=${encodeURIComponent(setupToken)}` : '/auth/oidc'"><KeyRoundIcon />{{ t('auth.continueWith', { provider: name }) }}</a>
    </Button>
  </div>
  <div v-if="separator" class="flex items-center gap-3 text-xs uppercase text-muted-foreground">
    <Separator class="flex-1" />{{ t('auth.or') }}<Separator class="flex-1" />
  </div>
</template>
