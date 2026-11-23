<script setup lang="ts">
import { CopyIcon, DownloadIcon, UploadIcon } from '@lucide/vue'
import { toast } from 'vue-sonner'

import type { CertificateAuthorityDetail } from '~/types/api'

/**
 * The steps for an externally signed CA: download the CSR, sign it with the outside root (an
 * OpenSSL example with the extensions certifly checks on import), import the result.
 */
const props = defineProps<{ ca: CertificateAuthorityDetail; canImport: boolean }>()
const emit = defineEmits<{ import: [] }>()
const { t } = useI18n()

const csr = computed(() => props.ca.pending_csr!)
const renewal = computed(() => !!props.ca.active_certificate)

/** OpenSSL writes IP constraints as address/netmask. */
function ipWithMask(cidr: string): string {
  const [address, bits] = cidr.split('/') as [string, string]
  const prefix = Number(bits)
  if (address.includes('.')) {
    const mask = [0, 1, 2, 3].map((i) => (0xff << (8 - Math.max(0, Math.min(8, prefix - i * 8)))) & 0xff)
    return `${address}/${mask.join('.')}`
  }
  const groups = Array.from({ length: 8 }, (_, i) => ((0xffff << (16 - Math.max(0, Math.min(16, prefix - i * 16)))) & 0xffff).toString(16))
  return `${address}/${groups.join(':')}`
}

const snippet = computed(() => {
  const nc = props.ca.name_constraints
  const entries = nc
    ? (['permitted', 'excluded'] as const).flatMap((side) => [
        ...nc[side].dns.map((v) => `${side};DNS:${v}`),
        ...nc[side].ip.map((v) => `${side};IP:${ipWithMask(v)}`),
        ...nc[side].email.map((v) => `${side};email:${v}`),
      ])
    : []
  const path = csr.value.requested_path_length
  const slug = props.ca.slug
  return [
    `cat > ${slug}.ext <<'EOF'`,
    '[v3_ca]',
    `basicConstraints = critical, CA:TRUE${path === null ? '' : `, pathlen:${path}`}`,
    'keyUsage = critical, keyCertSign, cRLSign, digitalSignature',
    `nameConstraints = critical, ${entries.join(', ')}`,
    'subjectKeyIdentifier = hash',
    'authorityKeyIdentifier = keyid',
    "# Add your root's own crlDistributionPoints and authorityInfoAccess here.",
    'EOF',
    `openssl x509 -req -in ${slug}.csr -CA root.pem -CAkey root.key -days 1825 \\`,
    `  -extfile ${slug}.ext -extensions v3_ca -out ${slug}.pem`,
  ].join('\n')
})

async function copy(text: string) {
  await navigator.clipboard.writeText(text)
  toast.success(t('common.copied'))
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle>{{ t('cas.csr.title') }}</CardTitle>
      <CardDescription>{{ renewal ? t('cas.csr.renewDescription') : t('cas.csr.description') }}</CardDescription>
    </CardHeader>
    <CardContent>
      <ol class="flex flex-col gap-6">
        <li class="flex flex-col gap-2">
          <span class="text-sm font-medium">1. {{ t('cas.csr.step1') }}</span>
          <div class="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" @click="downloadText(`${ca.slug}.csr`, csr.pem, 'application/pkcs10')"><DownloadIcon />{{ t('cas.csr.download') }}</Button>
            <Button variant="ghost" size="sm" @click="copy(csr.pem)"><CopyIcon />{{ t('cas.csr.copy') }}</Button>
          </div>
        </li>
        <li class="flex min-w-0 flex-col gap-2">
          <span class="text-sm font-medium">2. {{ t('cas.csr.step2') }}</span>
          <p class="text-sm text-muted-foreground">{{ t('cas.csr.step2Hint') }}</p>
          <div class="relative min-w-0">
            <pre class="overflow-x-auto rounded-md border bg-muted/40 p-3 pr-12 font-mono text-xs leading-relaxed">{{ snippet }}</pre>
            <Button variant="ghost" size="icon-sm" class="absolute top-1.5 right-1.5" :aria-label="t('cas.csr.copySnippet')" :title="t('cas.csr.copySnippet')" @click="copy(snippet)">
              <CopyIcon />
            </Button>
          </div>
        </li>
        <li class="flex flex-col gap-2">
          <span class="text-sm font-medium">3. {{ t('cas.csr.step3') }}</span>
          <div v-if="canImport">
            <Button size="sm" @click="emit('import')"><UploadIcon />{{ t('cas.detail.importCertificate') }}</Button>
          </div>
        </li>
      </ol>
    </CardContent>
  </Card>
</template>
