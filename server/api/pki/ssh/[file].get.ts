import { publicSshCaKey, publicSshKrl } from '@certifly/core/ssh-krl'

/**
 * An SSH CA's public files
 *
 * `GET /api/pki/ssh/<slug>.pub`: the CA public key as an authorized_keys line (`text/plain`), to
 * put in `TrustedUserCAKeys` or a `@cert-authority` line of known_hosts.
 * `GET /api/pki/ssh/<slug>.krl`: the current OpenSSH key revocation list (binary, `no-cache`),
 * for sshd's `RevokedKeys`. Public, no sign-in.
 */
export default defineEventHandler(async (event) => {
  await limit(event, 'sshHost', clientIp(event))
  const name = getRouterParam(event, 'file')
  const ctx = useContext()
  if (name?.endsWith('.pub')) {
    const slug = slugFromFile(name, '.pub')
    const ca = slug ? await publicSshCaKey(ctx, slug) : null
    if (!ca) throw notFound()
    return sendPkiFile(event, `${ca.public_key}\n`, { type: 'text/plain; charset=utf-8', filename: `${slug}.pub`, modified: ca.updated_at })
  }
  const slug = slugFromFile(name, '.krl')
  const krl = slug ? await publicSshKrl(ctx, slug) : null
  if (!krl) throw notFound()
  const body = sendPkiFile(event, krl.krl, { type: 'application/octet-stream', filename: `${slug}.krl`, modified: krl.generated_at })
  // Hosts must see a revocation as soon as it is made.
  setResponseHeader(event, 'cache-control', 'no-cache')
  return body
})
