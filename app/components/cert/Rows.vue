<script setup lang="ts">
import type { Certificate } from '~/types/api'

/** The certificate rows of the list: name with tags, status, template, CA and expiry. */
defineProps<{ rows: Certificate[]; loading?: boolean; empty?: string }>()
const { t, d } = useI18n()

const name = (cert: Certificate) => cert.common_name ?? cert.sans[0]?.value ?? t('certificates.untitled')
const others = (cert: Certificate) => cert.sans.filter((san) => san.value !== name(cert)).length
</script>

<template>
  <div class="overflow-x-auto rounded-md border">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{{ t('certificates.columns.name') }}</TableHead>
          <TableHead class="w-32">{{ t('certificates.columns.status') }}</TableHead>
          <TableHead class="hidden md:table-cell">{{ t('certificates.columns.template') }}</TableHead>
          <TableHead class="hidden lg:table-cell">{{ t('certificates.columns.ca') }}</TableHead>
          <TableHead>{{ t('certificates.columns.expires') }}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <template v-if="loading && !rows.length">
          <TableRow v-for="i in 3" :key="i">
            <TableCell v-for="j in 5" :key="j" :class="j === 3 ? 'hidden md:table-cell' : j === 4 ? 'hidden lg:table-cell' : ''"><Skeleton class="h-4 w-full" /></TableCell>
          </TableRow>
        </template>
        <TableRow v-else-if="!rows.length">
          <TableCell colspan="5" class="h-20 text-center text-muted-foreground">{{ empty ?? t('certificates.noMatches') }}</TableCell>
        </TableRow>
        <TableRow v-for="cert in rows" :key="cert.id" :class="loading && 'opacity-60'">
          <TableCell class="max-w-80">
            <NuxtLink :to="`/certificates/${cert.id}`" class="flex min-w-0 flex-col gap-1 underline-offset-4 hover:underline">
              <span class="truncate font-medium" :title="name(cert)">{{ name(cert) }}</span>
              <span class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                <span v-if="others(cert)">{{ t('certificates.moreNames', { count: others(cert) }) }}</span>
                <span>{{ t('certificates.issuedOn', { date: d(new Date(cert.created_at), { dateStyle: 'medium' }) }) }}</span>
              </span>
              <span v-if="cert.tags?.length" class="flex flex-wrap gap-1">
                <TagChip v-for="tag in cert.tags" :key="tag.id" :name="tag.name" :color="tag.color" />
              </span>
            </NuxtLink>
          </TableCell>
          <TableCell>
            <span class="flex flex-wrap items-center gap-1">
              <CertStatusBadge :status="cert.status" />
              <Badge v-if="cert.source === 'import'" variant="outline" class="text-muted-foreground">{{ t('certificates.sources.import') }}</Badge>
            </span>
          </TableCell>
          <TableCell class="hidden text-sm md:table-cell">{{ cert.template?.name ?? '—' }}</TableCell>
          <TableCell class="hidden max-w-56 truncate text-sm lg:table-cell" :title="cert.ca ? undefined : cert.issuer_dn">{{ cert.ca?.name ?? cert.issuer_dn }}</TableCell>
          <TableCell class="whitespace-nowrap"><CaExpiry :not-after="cert.not_after" /></TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>
