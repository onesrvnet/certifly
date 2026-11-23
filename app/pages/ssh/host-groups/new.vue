<script setup lang="ts">
import { toast } from 'vue-sonner'

import type { SshCa } from '~/types/api'

/** Create a host group: name, CA and host names, then the rules for user and host certificates. */
definePageMeta({ titleKey: 'sshHostGroups.new.title', requires: ['instance', 'manage_ssh_host_groups'] })

const { t } = useI18n()
const rpc = useRpc()
const router = useRouter()
const errorMessage = useErrorMessage()

useHead({ title: () => t('sshHostGroups.new.title') })
// Keep focused fields clear of the sticky page header and save bar.
useHead({ htmlAttrs: { style: 'scroll-padding: 5rem 0 5.5rem' } })

const { data: cas } = await useAsyncData(
  'ssh-host-group-cas',
  async () => {
    const all: SshCa[] = []
    let cursor: string | undefined
    do {
      const res = await rpc('ssh_cas.list', { cursor, limit: 200 })
      all.push(...res.data)
      cursor = res.next_cursor ?? undefined
    } while (cursor)
    return all
  },
  { default: () => [] as SshCa[] },
)

const form = ref(emptyHostGroupForm(cas.value[0]?.id))
const errors = ref<Partial<Record<HostGroupField, string>>>({})
const formError = ref('')
const ready = computed(() => !!form.value.name.trim() && !!form.value.ssh_ca_id && /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(form.value.slug))

const submit = useAction(async () => {
  errors.value = {}
  formError.value = ''
  try {
    const res = await rpc('ssh_host_groups.create', {
      ...hostGroupSettings(form.value),
      name: form.value.name.trim(),
      slug: form.value.slug,
      ssh_ca_id: form.value.ssh_ca_id,
    })
    toast.success(t('sshHostGroups.new.created', { name: res.data.name }))
    await router.push(`/ssh/host-groups/${res.data.id}`)
  } catch (error) {
    if (!(error instanceof RpcError) || (error.status !== 400 && error.status !== 409 && error.status !== 404)) throw error
    const field = hostGroupErrorField(error)
    if (field) errors.value = { [field]: errorMessage(error) }
    else formError.value = errorMessage(error)
  }
})
</script>

<template>
  <div class="mx-auto flex w-full max-w-3xl flex-col gap-6 p-4 md:p-10">
    <form class="flex min-w-0 flex-col gap-6" @submit.prevent="submit()">
      <Alert v-if="formError" class="border-danger/40 bg-danger-soft text-danger">
        <AlertDescription class="text-foreground">{{ formError }}</AlertDescription>
      </Alert>
      <SshHostGroupForm v-model="form" :cas="cas" mode="create" :errors="errors" />
      <div class="sticky bottom-0 z-10 flex flex-wrap justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <Button type="button" variant="outline" as-child><NuxtLink to="/ssh/host-groups">{{ t('common.cancel') }}</NuxtLink></Button>
        <Button type="submit" :loading="submit.busy" :disabled="!ready">{{ t('sshHostGroups.new.submit') }}</Button>
      </div>
    </form>
  </div>
</template>
