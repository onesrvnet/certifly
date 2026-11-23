<script setup lang="ts">
import { CircleAlertIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateAuthorityDetail } from '~/types/api'

/**
 * Import the certificate an outside root signed, with its chain: pasted or from files. When the
 * server refuses it, every problem it found is listed here, so the root operator knows what to fix.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ ca: CertificateAuthorityDetail }>()
const emit = defineEmits<{ imported: [ca: CertificateAuthorityDetail] }>()
const { t, te } = useI18n()
const rpc = useRpc()
const errorMessage = useErrorMessage()

const certificate = ref('')
const chain = ref('')
const problems = ref<{ code: string; message: string }[]>([])

watch(open, (value) => {
  if (!value) return
  certificate.value = ''
  chain.value = ''
  problems.value = []
})

async function load(event: Event, target: Ref<string>) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (file) target.value = await readCertificateFile(file)
  ;(event.target as HTMLInputElement).value = ''
}
const loadCertificate = (event: Event) => load(event, certificate)
const loadChain = (event: Event) => load(event, chain)

const problemText = (problem: { code: string; message: string }) => (te(`cas.importErrors.${problem.code}`) ? t(`cas.importErrors.${problem.code}`) : problem.message)

const submit = useAction(async () => {
  problems.value = []
  try {
    const res = await rpc('certificate_authorities.import', { id: props.ca.id, certificate: certificate.value.trim(), chain: chain.value.trim() })
    toast.success(t('cas.import.imported'))
    open.value = false
    emit('imported', res.data)
  } catch (error) {
    // Re-authentication goes back to useAction, which asks and then retries.
    if (isReauthRequired(error)) throw error
    const listed = error instanceof RpcError ? (error.details?.errors as { code: string; message: string }[] | undefined) : undefined
    problems.value = listed?.length ? listed : [{ code: error instanceof RpcError ? error.code : 'unknown', message: errorMessage(error) }]
  }
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>{{ t('cas.import.title') }}</DialogTitle>
        <DialogDescription>{{ t('cas.import.description') }}</DialogDescription>
      </DialogHeader>
      <form class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
        <Alert v-if="problems.length" variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>{{ t('cas.import.refused') }}</AlertTitle>
          <AlertDescription>
            <ul class="list-disc pl-4">
              <li v-for="problem in problems" :key="problem.code + problem.message">{{ problemText(problem) }}</li>
            </ul>
          </AlertDescription>
        </Alert>
        <FieldGroup>
          <Field>
            <div class="flex items-center justify-between gap-2">
              <FieldLabel for="import-certificate">{{ t('cas.import.certificate') }}</FieldLabel>
              <label class="cursor-pointer text-xs text-primary underline-offset-4 hover:underline">
                {{ t('cas.import.chooseFile') }}
                <input type="file" accept=".pem,.crt,.cer,.der" class="sr-only" @change="loadCertificate" />
              </label>
            </div>
            <Textarea id="import-certificate" v-model="certificate" rows="6" spellcheck="false" class="font-mono text-xs" :placeholder="t('cas.import.certificatePlaceholder')" />
          </Field>
          <Field>
            <div class="flex items-center justify-between gap-2">
              <FieldLabel for="import-chain">{{ t('cas.import.chain') }}</FieldLabel>
              <label class="cursor-pointer text-xs text-primary underline-offset-4 hover:underline">
                {{ t('cas.import.chooseFile') }}
                <input type="file" accept=".pem,.crt,.cer" class="sr-only" @change="loadChain" />
              </label>
            </div>
            <Textarea id="import-chain" v-model="chain" rows="6" spellcheck="false" class="font-mono text-xs" :placeholder="t('cas.import.certificatePlaceholder')" />
            <FieldDescription>{{ t('cas.import.chainHint') }}</FieldDescription>
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!certificate.trim()">{{ t('cas.import.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
