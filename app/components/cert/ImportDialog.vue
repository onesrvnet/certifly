<script setup lang="ts">
import { CircleCheckIcon, InfoIcon, TagIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { ImportResult, Tag } from '~/types/api'

/**
 * Import certificates issued elsewhere into the inventory, pasted or from a file. Afterwards it
 * says what was added and what was skipped (already known, or a CA certificate from a chain).
 */
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ imported: [result: ImportResult] }>()
const { t } = useI18n()
const rpc = useRpc()

const pem = ref('')
const notes = ref('')
const tagIds = ref<string[]>([])
const { data: allTags } = useLazyAsyncData('import-tags', async () => (await rpc('tags.list')).data, { default: () => [] as Tag[] })
const pickedTags = computed(() => allTags.value.filter((tag) => tagIds.value.includes(tag.id)))
const result = ref<ImportResult | null>(null)

watch(open, (value) => {
  if (!value) return
  pem.value = ''
  notes.value = ''
  tagIds.value = []
  result.value = null
})

async function load(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (file) pem.value = await readCertificateFile(file)
  ;(event.target as HTMLInputElement).value = ''
}

const submit = useAction(async () => {
  const res = await rpc('certificates.import', { pem: pem.value.trim(), notes: notes.value.trim() || undefined, tag_ids: tagIds.value.length ? tagIds.value : undefined })
  result.value = res.data
  if (res.data.imported.length) toast.success(t('certificates.import.imported', { count: res.data.imported.length }))
  emit('imported', res.data)
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>{{ t('certificates.import.title') }}</DialogTitle>
        <DialogDescription>{{ t('certificates.import.description') }}</DialogDescription>
      </DialogHeader>

      <div v-if="result" class="flex min-w-0 flex-col gap-4">
        <Alert v-if="result.imported.length">
          <CircleCheckIcon />
          <AlertTitle>{{ t('certificates.import.importedTitle', { count: result.imported.length }) }}</AlertTitle>
          <AlertDescription>
            <ul class="flex flex-col gap-1">
              <li v-for="cert in result.imported" :key="cert.id" class="min-w-0">
                <NuxtLink :to="`/certificates/${cert.id}`" class="font-medium break-all text-primary underline-offset-4 hover:underline" @click="open = false">
                  {{ cert.common_name ?? cert.subject_dn ?? cert.serial }}
                </NuxtLink>
              </li>
            </ul>
          </AlertDescription>
        </Alert>
        <Alert v-if="result.skipped.length">
          <InfoIcon />
          <AlertTitle>{{ t('certificates.import.skippedTitle', { count: result.skipped.length }) }}</AlertTitle>
          <AlertDescription>
            <ul class="flex flex-col gap-1">
              <li v-for="skip in result.skipped" :key="skip.fingerprint_sha256" class="min-w-0 break-all">
                <span class="font-mono text-xs">{{ skip.subject || skip.fingerprint_sha256 }}</span>
                — {{ t(`certificates.import.reasons.${skip.reason}`) }}
                <NuxtLink v-if="skip.certificate_id" :to="`/certificates/${skip.certificate_id}`" class="text-primary underline-offset-4 hover:underline" @click="open = false">
                  {{ t('certificates.import.open') }}
                </NuxtLink>
              </li>
            </ul>
          </AlertDescription>
        </Alert>
        <DialogFooter>
          <Button variant="outline" @click="result = null">{{ t('certificates.import.again') }}</Button>
          <Button @click="open = false">{{ t('common.done') }}</Button>
        </DialogFooter>
      </div>

      <form v-else class="flex min-w-0 flex-col gap-4" @submit.prevent="submit()">
        <FieldGroup>
          <Field>
            <div class="flex items-center justify-between gap-2">
              <FieldLabel for="inventory-pem">{{ t('certificates.import.pem') }}</FieldLabel>
              <label class="cursor-pointer text-xs text-primary underline-offset-4 hover:underline">
                {{ t('certificates.import.chooseFile') }}
                <input type="file" accept=".pem,.crt,.cer,.der" class="sr-only" @change="load" />
              </label>
            </div>
            <Textarea id="inventory-pem" v-model="pem" rows="8" spellcheck="false" class="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" />
            <FieldDescription>{{ t('certificates.import.pemHint') }}</FieldDescription>
          </Field>
          <Field>
            <FieldLabel for="inventory-notes">{{ t('certificates.import.notes') }}</FieldLabel>
            <Input id="inventory-notes" v-model="notes" maxlength="2000" :placeholder="t('certificates.import.notesPlaceholder')" />
          </Field>
          <Field>
            <FieldLabel>{{ t('tags.title') }}</FieldLabel>
            <div class="flex flex-wrap items-center gap-1.5">
              <TagChip v-for="tag in pickedTags" :key="tag.id" :name="tag.name" :color="tag.color" />
              <TagPicker v-model="tagIds" :tags="allTags">
                <Button type="button" variant="outline" size="sm"><TagIcon />{{ t('tags.editTags') }}</Button>
              </TagPicker>
            </div>
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">{{ t('common.cancel') }}</Button>
          <Button type="submit" :loading="submit.busy" :disabled="!pem.trim()">{{ t('certificates.import.submit') }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
