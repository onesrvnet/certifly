<script setup lang="ts">
import { EllipsisIcon } from '@lucide/vue'

import type { SshCertificate } from '~/types/api'

/** The rows of an SSH certificate list: key ID, principals, who or what it is for, status and expiry. */
defineProps<{ rows: SshCertificate[]; loading?: boolean; empty?: string }>()
const emit = defineEmits<{ revoke: [certificate: SshCertificate] }>()
const { t, d, locale } = useI18n()

/** The person's name or the host's name, when the API names them. */
const subjectOf = (cert: SshCertificate) => {
  const person = cert.user as { name?: string } | null
  const host = cert.host as { name?: string } | null
  return cert.kind === 'user' ? (person?.name ?? null) : (host?.name ?? null)
}
</script>

<template>
  <div class="overflow-x-auto rounded-md border">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{{ t('sshCerts.columns.keyId') }}</TableHead>
          <TableHead class="hidden md:table-cell">{{ t('sshCerts.columns.principals') }}</TableHead>
          <TableHead class="w-28">{{ t('sshCerts.columns.status') }}</TableHead>
          <TableHead>{{ t('sshCerts.columns.expires') }}</TableHead>
          <TableHead class="w-12"><span class="sr-only">{{ t('sshCerts.columns.actions') }}</span></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <template v-if="loading && !rows.length">
          <TableRow v-for="i in 3" :key="i">
            <TableCell v-for="j in 5" :key="j" :class="j === 2 ? 'hidden md:table-cell' : ''"><Skeleton class="h-4 w-full" /></TableCell>
          </TableRow>
        </template>
        <TableRow v-else-if="!rows.length">
          <TableCell colspan="5" class="h-20 text-center text-muted-foreground">{{ empty ?? t('sshCerts.noMatches') }}</TableCell>
        </TableRow>
        <TableRow v-for="cert in rows" :key="cert.id" :class="loading && 'opacity-60'">
          <TableCell class="max-w-80">
            <span class="flex min-w-0 flex-col gap-1">
              <span class="truncate font-mono text-xs font-medium" :title="cert.key_id">{{ cert.key_id }}</span>
              <span class="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <Badge variant="outline" class="text-muted-foreground">{{ t(`sshCerts.kinds.${cert.kind}`) }}</Badge>
                <span v-if="subjectOf(cert)">{{ subjectOf(cert) }}</span>
                <span>{{ t('sshCerts.signedOn', { date: d(new Date(cert.created_at), { dateStyle: 'medium' }) }) }}</span>
              </span>
              <span class="flex flex-wrap gap-1 md:hidden">
                <Badge v-for="principal in cert.principals" :key="principal" variant="secondary" class="font-mono text-xs">{{ principal }}</Badge>
              </span>
            </span>
          </TableCell>
          <TableCell class="hidden max-w-80 md:table-cell">
            <span class="flex flex-wrap gap-1">
              <Badge v-for="principal in cert.principals" :key="principal" variant="secondary" class="font-mono text-xs">{{ principal }}</Badge>
            </span>
          </TableCell>
          <TableCell><CertStatusBadge :status="cert.status" /></TableCell>
          <TableCell class="whitespace-nowrap">
            <span class="flex flex-col gap-0.5 text-xs text-muted-foreground">
              <time :datetime="cert.valid_before" :title="cert.valid_before">{{ d(new Date(cert.valid_before), { dateStyle: 'medium', timeStyle: 'short' }) }}</time>
              <span v-if="cert.status === 'active'">{{ t('sshCerts.expiresIn', { time: timeAgo(cert.valid_before, locale) }) }}</span>
              <span v-else-if="cert.status === 'revoked' && cert.revoked_at">{{ t('sshCerts.revokedAgo', { time: timeAgo(cert.revoked_at, locale) }) }}</span>
            </span>
          </TableCell>
          <TableCell class="text-right">
            <DropdownMenu v-if="cert.permissions.revoke">
              <DropdownMenuTrigger as-child>
                <Button variant="ghost" size="icon-sm" :icon="EllipsisIcon" :aria-label="t('sshCerts.moreActions')" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem variant="destructive" @select="emit('revoke', cert)">{{ t('sshCerts.revoke.action') }}</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>
