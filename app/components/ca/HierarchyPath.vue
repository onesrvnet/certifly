<script setup lang="ts">
import type { RpcOutput } from '~/types/api'

type Detail = RpcOutput<'certificate_authorities.get'>['data']

/**
 * Where a CA sits: the path from the root down to it, then the CAs it signed. Issuers outside
 * certifly (an external root, say) come from the imported chain and are shown without a link.
 */
const props = defineProps<{ ca: Detail }>()
const { t } = useI18n()

interface Node {
  key: string
  name: string
  id?: string
  role: 'root' | 'intermediate' | 'external' | 'outside'
  status?: Detail['status']
  revoked?: boolean
  not_after: string | null
}

const sameDn = (a: string, b: string) => a.replace(/\s+/g, '').toLowerCase() === b.replace(/\s+/g, '').toLowerCase()

const roleOf = (signing: Detail['signing']): Node['role'] => (signing === 'self_signed' ? 'root' : signing === 'internal' ? 'intermediate' : 'external')

const above = computed<Node[]>(() => {
  const inside = props.ca.ancestors
  // Issuers in the chain that certifly does not hold, root first.
  const outside = props.ca.chain
    .filter((link) => !inside.some((entry) => sameDn(entry.subject_dn, link.subject)))
    .reverse()
    .map<Node>((link) => ({ key: link.fingerprint_sha256, name: commonNameOf(link.subject), role: 'outside', not_after: link.not_after }))
  return [
    ...outside,
    ...inside.map<Node>((entry) => ({ key: entry.id, id: entry.id, name: entry.name, role: roleOf(entry.signing), status: entry.status, revoked: !!entry.revoked_at, not_after: entry.not_after })),
  ]
})

const root = computed(() => above.value[0]?.name ?? props.ca.name)
</script>

<template>
  <Card>
    <CardHeader>
      <div class="flex items-center gap-1.5">
        <CardTitle>{{ t('cas.hierarchy.title') }}</CardTitle>
        <InfoTip :text="ca.signing === 'self_signed' ? t('cas.hierarchy.hintRoot') : t('cas.hierarchy.hint', { root })" />
      </div>
    </CardHeader>
    <CardContent>
      <ol class="relative flex flex-col">
        <li v-for="node in above" :key="node.key" class="relative flex gap-3 pb-5">
          <span class="absolute top-4 bottom-0 left-[0.4375rem] w-px bg-border" aria-hidden="true" />
          <span class="relative mt-1 size-3.5 shrink-0 rounded-full border-2 border-muted-foreground/60 bg-muted-foreground/60" aria-hidden="true" />
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <div class="flex flex-wrap items-center gap-2">
              <NuxtLink v-if="node.id" :to="`/certificate-authorities/${node.id}`" class="font-medium text-primary underline-offset-4 hover:underline">{{ node.name }}</NuxtLink>
              <span v-else class="font-medium break-words">{{ node.name }}</span>
              <Badge variant="outline" class="text-muted-foreground">{{ t(`cas.hierarchy.roles.${node.role}`) }}</Badge>
              <CaStatusBadge v-if="node.status" :status="node.status" :revoked="node.revoked" />
            </div>
            <CaExpiry :not-after="node.not_after" />
          </div>
        </li>

        <li class="relative flex gap-3" :class="{ 'pb-5': ca.children.length > 0 }">
          <span v-if="ca.children.length" class="absolute top-4 bottom-0 left-[0.4375rem] w-px bg-border" aria-hidden="true" />
          <span class="relative mt-1 size-3.5 shrink-0 rounded-full border-2 border-primary bg-background ring-4 ring-brand-soft" aria-hidden="true" />
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-semibold">{{ ca.name }}</span>
              <Badge class="border-transparent bg-brand-soft text-primary">{{ t('cas.hierarchy.thisCa') }}</Badge>
              <Badge variant="outline" class="text-muted-foreground">{{ t(`cas.hierarchy.roles.${roleOf(ca.signing)}`) }}</Badge>
              <CaStatusBadge :status="ca.status" :revoked="!!ca.revoked_at" />
            </div>
            <CaExpiry :not-after="ca.not_after" />
          </div>
        </li>

        <li v-for="(child, index) in ca.children" :key="child.id" class="relative flex gap-3 pl-6" :class="index < ca.children.length - 1 && 'pb-3'">
          <span class="absolute top-0 left-[0.4375rem] w-px bg-border" :class="index < ca.children.length - 1 ? 'bottom-0' : 'h-3'" aria-hidden="true" />
          <span class="absolute top-3 left-[0.4375rem] h-px w-4 bg-border" aria-hidden="true" />
          <span class="relative mt-1 size-3 shrink-0 rounded-full border-2 border-muted-foreground/60 bg-background" aria-hidden="true" />
          <div class="flex min-w-0 flex-1 flex-wrap items-center gap-2">
            <NuxtLink :to="`/certificate-authorities/${child.id}`" class="font-medium text-primary underline-offset-4 hover:underline">{{ child.name }}</NuxtLink>
            <Badge variant="outline" class="text-muted-foreground">{{ t('cas.hierarchy.roles.intermediate') }}</Badge>
            <CaStatusBadge :status="child.status" :revoked="!!child.revoked_at" />
          </div>
        </li>
      </ol>
      <p v-if="!ca.children.length" class="mt-4 text-sm text-muted-foreground">{{ t('cas.hierarchy.noChildren') }}</p>
    </CardContent>
  </Card>
</template>
