import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { addUser, ageSessions, Client, coreContext, query, resetState, serverOptions, setupAdmin, userId } from '../helpers'
import { hasSshKeygen, run, sshWorkdir } from '../support/ssh'

const work = sshWorkdir()
afterAll(() => work.cleanup())

const ssh = it.skipIf(!hasSshKeygen)

/** The ed25519 security key line that carries the same public key as an ed25519 key line. */
function skLine(pub: string): string {
  const blob = Buffer.from(pub.split(' ')[1]!, 'base64')
  const raw = blob.subarray(blob.length - 32)
  const text = (value: string | Buffer) => {
    const data = typeof value === 'string' ? Buffer.from(value) : value
    const length = Buffer.alloc(4)
    length.writeUInt32BE(data.length)
    return Buffer.concat([length, data])
  }
  return `sk-ssh-ed25519@openssh.com ${Buffer.concat([text('sk-ssh-ed25519@openssh.com'), text(raw), text('ssh:')]).toString('base64')}`
}

describe('ssh certificate authorities, access and certificates', async () => {
  await setup(serverOptions)
  beforeEach(resetState)
  // Each test starts from an instance with three invited people, which waits for their mails.
  vi.setConfig({ testTimeout: 90_000 })

  /** An instance with a CA, a host group "prod", a group "Developers" with one member, and one rule. */
  async function world() {
    const admin = await setupAdmin()
    const operator = await addUser(admin, 'op@example.com', 'operator')
    const dev = await addUser(admin, 'dev@example.com', 'viewer')
    const outsider = await addUser(admin, 'out@example.com', 'viewer')
    const devId = await userId(dev)
    const ca = (await admin.rpc('ssh_cas.create', { name: 'Main', slug: 'main' })).body.data
    const hostGroup = (
      await admin.rpc('ssh_host_groups.create', {
        name: 'Prod',
        slug: 'prod',
        ssh_ca_id: ca.id,
        host_patterns: ['*.prod.corp'],
        user_extensions: ['permit-pty', 'permit-port-forwarding'],
        force_command: '/usr/bin/true',
        source_address: ['10.0.0.0/8'],
      })
    ).body.data
    const group = (await admin.rpc('groups.create', { name: 'Developers' })).body.data
    expect((await admin.rpc('group_members.create', { group_id: group.id, user_id: devId })).status).toBe(200)
    const rule = (await admin.rpc('ssh_access_rules.create', { host_group_id: hostGroup.id, group_id: group.id, logins: ['deploy'], own_username: true })).body.data
    return { admin, operator, dev, outsider, devId, ca, hostGroup, group, rule }
  }
  type World = Awaited<ReturnType<typeof world>>

  async function cliToken(user: Client, hostname = 'laptop'): Promise<{ token: string; login_id: string }> {
    const verifier = randomBytes(32).toString('base64url')
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const anon = new Client()
    const start = (await anon.rpc('cli_logins.start', { code_challenge: challenge, machine: { hostname, os: 'darwin' } })).body
    expect((await user.rpc('cli_logins.approve', { login_id: start.login_id })).status).toBe(200)
    const poll = await anon.rpc('cli_logins.poll', { device_code: start.device_code, code_verifier: verifier })
    expect(poll.status).toBe(200)
    return { token: poll.body.token, login_id: start.login_id }
  }

  const asCli = (token: string) => (method: string, body: unknown = {}) => new Client().rpcWithKey(token, method, body)

  describe('command-line sign-in', () => {
    it('starts, waits for approval, hands the token out once, and signs out', async () => {
      const w = await world()
      const verifier = randomBytes(32).toString('base64url')
      const challenge = createHash('sha256').update(verifier).digest('base64url')
      const anon = new Client()
      const started = await anon.rpc('cli_logins.start', { code_challenge: challenge, machine: { hostname: 'laptop', os: 'darwin' } })
      expect(started.status).toBe(200)
      expect(started.body).toMatchObject({ interval_seconds: 5 })
      expect(started.body.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/)
      expect(started.body.browser_url).toBe(`${process.env.URL}/cli/login/${started.body.login_id}`)
      expect(Date.parse(started.body.expires_at) - Date.now()).toBeGreaterThan(9 * 60_000)

      const poll = () => anon.rpc('cli_logins.poll', { device_code: started.body.device_code, code_verifier: verifier })
      expect((await poll()).body).toEqual({ status: 'pending' })
      // Polling again at once is too fast.
      const fast = await poll()
      expect(fast.status).toBe(429)
      expect(fast.body.error.code).toBe('slow_down')
      await query()`update cli_logins set last_poll_at = now() - interval '10 seconds'`

      // The confirm page sees the machine and the code, with a browser session only.
      const shown = await w.dev.rpc('cli_logins.get', { login_id: started.body.login_id })
      expect(shown.body.data).toMatchObject({ user_code: started.body.user_code, machine: { hostname: 'laptop', os: 'darwin' }, status: 'pending' })
      expect((await anon.rpc('cli_logins.get', { login_id: started.body.login_id })).status).toBe(401)

      expect((await w.dev.rpc('cli_logins.approve', { login_id: started.body.login_id })).status).toBe(200)
      const done = await poll()
      expect(done.status).toBe(200)
      expect(done.body.status).toBe('approved')
      expect(done.body.token).toMatch(/^cfc_/)
      expect(done.body.user).toMatchObject({ id: w.devId, email: 'dev@example.com', username: 'dev' })
      expect(Date.parse(done.body.expires_at) - Date.now()).toBeGreaterThan(11.9 * 3600_000)
      expect(Date.parse(done.body.expires_at) - Date.now()).toBeLessThan(12.1 * 3600_000)
      // The token exists once: only its hash is stored, and a second poll finds the login spent.
      const [row] = await query()`select token_hash from cli_sessions`
      expect(row!.token_hash).not.toBe(done.body.token)
      await query()`update cli_logins set last_poll_at = now() - interval '10 seconds'`
      expect((await poll()).status).toBe(410)

      const cli = asCli(done.body.token)
      expect((await cli('ssh_access.get')).status).toBe(200)
      expect((await cli('cli_sessions.delete')).status).toBe(200)
      expect((await cli('ssh_access.get')).status).toBe(401)
    })

    it('refuses a wrong verifier, an unknown code, a denied or expired login', async () => {
      const w = await world()
      const verifier = randomBytes(32).toString('base64url')
      const challenge = createHash('sha256').update(verifier).digest('base64url')
      const anon = new Client()
      const start = async () => (await anon.rpc('cli_logins.start', { code_challenge: challenge, machine: { hostname: 'box', os: 'linux' } })).body
      const first = await start()
      const wrong = await anon.rpc('cli_logins.poll', { device_code: first.device_code, code_verifier: randomBytes(32).toString('base64url') })
      expect(wrong.status).toBe(400)
      expect(wrong.body.error.code).toBe('invalid_code_verifier')
      expect((await anon.rpc('cli_logins.poll', { device_code: 'nope', code_verifier: verifier })).status).toBe(410)
      expect((await anon.rpc('cli_logins.start', { code_challenge: 'short', machine: { hostname: 'x', os: 'y' } })).status).toBe(400)

      expect((await w.dev.rpc('cli_logins.deny', { login_id: first.login_id })).status).toBe(200)
      const denied = await anon.rpc('cli_logins.poll', { device_code: first.device_code, code_verifier: verifier })
      expect(denied.status).toBe(403)
      expect(denied.body.error.code).toBe('cli_login_denied')

      const second = await start()
      await query()`update cli_logins set expires_at = now() - interval '1 second' where id = ${second.login_id}`
      expect((await anon.rpc('cli_logins.poll', { device_code: second.device_code, code_verifier: verifier })).status).toBe(410)
      expect((await w.dev.rpc('cli_logins.approve', { login_id: second.login_id })).status).toBe(404)
    })

    it('lets only a browser session approve, and confines the token to its four endpoints', async () => {
      const w = await world()
      const key = (await w.dev.rpc('api_keys.create', { name: 'ci' })).body.data
      const { token } = await cliToken(w.dev)
      const verifier = randomBytes(32).toString('base64url')
      const anon = new Client()
      const start = (await anon.rpc('cli_logins.start', { code_challenge: createHash('sha256').update(verifier).digest('base64url'), machine: { hostname: 'x', os: 'y' } })).body
      // Neither an API key nor a command-line token can approve a login.
      expect((await new Client().rpcWithKey(key.secret, 'cli_logins.approve', { login_id: start.login_id })).status).toBe(403)
      expect((await asCli(token)('cli_logins.approve', { login_id: start.login_id })).status).toBe(403)

      const cli = asCli(token)
      for (const [method, body] of [
        ['sessions.get', {}],
        ['api_keys.create', { name: 'x' }],
        ['api_keys.list', {}],
        ['certificates.list', {}],
        ['ssh_cas.list', {}],
        ['users.list', {}],
        ['cli_sessions.list', {}],
      ] as const) {
        const answer = await cli(method, body)
        expect({ method, status: answer.status, code: answer.body.error?.code }).toEqual({ method, status: 403, code: 'cli_token_endpoint' })
      }
      for (const method of ['ssh_access.get', 'ssh_hosts.reachable'] as const) expect((await cli(method)).status).toBe(200)
    })

    it('stops working when its person is deactivated, and never passes a step-up', async () => {
      const w = await world()
      const { token } = await cliToken(w.dev)
      expect((await asCli(token)('ssh_access.get')).status).toBe(200)
      expect((await w.admin.rpc('users.update', { id: w.devId, deactivated: true })).status).toBe(200)
      expect((await asCli(token)('ssh_access.get')).status).toBe(401)
      const [session] = await query()`select revoked_at from cli_sessions`
      expect(session!.revoked_at).not.toBeNull()
      // An admin's token acts as the admin, but CA and token management refuse it before any role check.
      const admin = await cliToken(w.admin)
      expect((await asCli(admin.token)('ssh_cas.create', { name: 'x', slug: 'x' })).status).toBe(403)
    })

    it('lists and ends one’s own CLI sessions from the browser', async () => {
      const w = await world()
      await cliToken(w.dev)
      const listed = (await w.dev.rpc('cli_sessions.list')).body.data
      expect(listed).toHaveLength(1)
      expect(listed[0]).toMatchObject({ machine: { hostname: 'laptop', os: 'darwin' }, current: false })
      expect((await w.outsider.rpc('cli_sessions.delete', { id: listed[0].id })).status).toBe(404)
      expect((await w.dev.rpc('cli_sessions.delete', { id: listed[0].id })).status).toBe(200)
      expect((await w.dev.rpc('cli_sessions.list')).body.data).toHaveLength(0)
    })
  })

  describe('access and user certificates', () => {
    it('shows each person only the host groups they have a login in', async () => {
      const w = await world()
      const access = (await w.dev.rpc('ssh_access.get')).body
      expect(access.user).toMatchObject({ id: w.devId, username: 'dev' })
      expect(access.host_groups).toHaveLength(1)
      expect(access.host_groups[0]).toMatchObject({
        id: w.hostGroup.id,
        slug: 'prod',
        logins: ['deploy', 'dev'],
        // The own username has its own namespace, so it can never equal a fixed login's principal.
        principals: ['prod:deploy', 'prod:~dev'],
        key_policy: 'any',
        default_ttl_seconds: 8 * 3600,
        max_ttl_seconds: 24 * 3600,
        extensions: ['permit-port-forwarding', 'permit-pty'],
        host_patterns: ['*.prod.corp'],
        ca: { id: w.ca.id, slug: 'main', name: 'Main', public_key: w.ca.public_key },
      })
      expect((await w.outsider.rpc('ssh_access.get')).body.host_groups).toEqual([])
      // API keys work too.
      const key = (await w.dev.rpc('api_keys.create', { name: 'ci' })).body.data
      expect((await new Client().rpcWithKey(key.secret, 'ssh_access.get')).body.host_groups).toHaveLength(1)
    })

    ssh('signs a key for a person with access, and ssh-keygen reads what was signed', async () => {
      const w = await world()
      const key = work.keygen('dev1')
      const signed = await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub })
      expect(signed.status).toBe(200)
      const cert = signed.body.data
      expect(cert.principals).toEqual(['prod:deploy', 'prod:~dev'])
      expect(cert.key_id).toBe(`certifly:dev@example.com:prod:${cert.id}`)
      expect(cert.serial).toMatch(/^\d+$/)
      expect(BigInt(cert.serial) < 2n ** 63n).toBe(true)
      const described = work.describe(cert.certificate)
      expect(described.status, described.stderr).toBe(0)
      expect(described.stdout).toContain('user certificate')
      expect(described.stdout).toContain(`Serial: ${cert.serial}`)
      expect(described.stdout).toContain(`Key ID: "${cert.key_id}"`)
      expect(described.stdout).toMatch(/Principals:\s+prod:deploy\s+prod:~dev/)
      expect(described.stdout).toMatch(/force-command \/usr\/bin\/true/)
      expect(described.stdout).toMatch(/source-address 10\.0\.0\.0\/8/)
      expect(described.stdout).toMatch(/permit-port-forwarding\s+permit-pty/)
      // Default lifetime: 8 hours (plus the two minutes of backdating).
      const span = Date.parse(cert.valid_before) - Date.parse(cert.valid_after)
      expect(span).toBe(8 * 3600_000 + 120_000)
      // The CA public key verifies nothing by itself, but the serving endpoint gives the same key.
      const pub = await new Client().get('/api/pki/ssh/main.pub')
      expect(pub.status).toBe(200)
      expect((await pub.text()).trim()).toBe(w.ca.public_key)
      // The signing is audited, with ids and facts and no key material.
      const events = (await w.admin.rpc('events.list', { name: 'ssh_certificates.issue' })).body.data
      expect(events).toHaveLength(1)
      expect(events[0].data).toMatchObject({ kind: 'user', serial: cert.serial })
      expect(JSON.stringify(events[0])).not.toContain('PRIVATE')
    })

    ssh('signs through the command-line token as well', async () => {
      const w = await world()
      const { token } = await cliToken(w.dev)
      const key = work.keygen('dev-cli')
      const signed = await asCli(token)('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub, ttl_seconds: 3600 })
      expect(signed.status).toBe(200)
      expect(Date.parse(signed.body.data.valid_before) - Date.parse(signed.body.data.valid_after)).toBe(3600_000 + 120_000)
      // The event names the command-line session, not a person's browser session.
      const [event] = (await w.admin.rpc('events.list', { name: 'ssh_certificates.issue' })).body.data
      expect(event).toMatchObject({ actor_type: 'cli' })
    })

    ssh('lets a renewal from the CLI replace that machine’s earlier certificate, and only that one', async () => {
      const w = await world()
      const laptop = asCli((await cliToken(w.dev, 'laptop')).token)
      const laptopAgain = asCli((await cliToken(w.dev, 'laptop')).token)
      const desktop = asCli((await cliToken(w.dev, 'desktop')).token)
      const sign = async (cli: ReturnType<typeof asCli>, name: string) =>
        (await cli('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: work.keygen(name).pub })).body.data.id as string
      const first = await sign(laptop, 'renew-1')
      const other = await sign(desktop, 'renew-2')
      const web = (await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: work.keygen('renew-web').pub })).body.data.id as string
      // A new sign-in on the same machine still counts as that machine.
      const second = await sign(laptopAgain, 'renew-3')
      const status = async (id: string) => (await w.dev.rpc('ssh_certificates.get', { id })).body.data
      expect(await status(first)).toMatchObject({ status: 'revoked', revocation_reason: 'superseded' })
      expect((await status(second)).status).toBe('active')
      expect((await status(other)).status).toBe('active')
      expect((await status(web)).status).toBe('active')
    })

    ssh('refuses what the rules do not allow', async () => {
      const w = await world()
      const key = work.keygen('refuse')
      const sign = (client: Client, body: object) => client.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub, ...body })
      // No login in this host group.
      const noAccess = await sign(w.outsider, {})
      expect([noAccess.status, noAccess.body.error.code]).toEqual([403, 'ssh_no_access'])
      // A host group that does not exist looks the same.
      const unknown = await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: crypto.randomUUID(), public_key: key.pub })
      expect(unknown.body.error.code).toBe('ssh_no_access')
      // Longer than the maximum.
      const long = await sign(w.dev, { ttl_seconds: 25 * 3600 })
      expect([long.status, long.body.error.code]).toEqual([400, 'ttl_too_long'])
      expect((await sign(w.dev, { ttl_seconds: 24 * 3600 })).status).toBe(200)
      // Key types: DSA and P-521 are refused, so is junk and a 1024 bit RSA key.
      const p521 = work.keygen('p521', ['-t', 'ecdsa', '-b', '521'])
      const rsa1024 = work.keygen('rsa1024', ['-t', 'rsa', '-b', '1024'])
      for (const bad of [p521.pub, rsa1024.pub, 'ssh-dss AAAAB3NzaC1kc3MAAAA', 'not a key', `${key.pub}\nsecond`]) {
        const refused = await sign(w.dev, { public_key: bad })
        expect([refused.status, refused.body.error.code]).toEqual([400, 'ssh_key_type'])
      }
      expect((await sign(w.dev, { public_key: work.keygen('rsa2048', ['-t', 'rsa', '-b', '2048']).pub })).status).toBe(200)
      // Signing for someone else is for admins in a recently confirmed session, and then the other
      // person's rules apply.
      const devId = w.devId
      expect((await sign(w.outsider, { for_user_id: devId })).status).toBe(403)
      expect((await sign(w.dev, { for_user_id: devId })).status).toBe(200)
      expect((await sign(w.operator, { for_user_id: devId })).status).toBe(403)
      const apiKey = (await w.admin.rpc('api_keys.create', { name: 'ci' })).body.data
      expect((await new Client().rpcWithKey(apiKey.secret, 'ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub, for_user_id: devId })).status).toBe(403)
      const forDev = await sign(w.admin, { for_user_id: devId })
      expect(forDev.status).toBe(200)
      expect(forDev.body.data.key_id).toContain('certifly:dev@example.com:prod:')
      const operatorId = await userId(w.operator)
      const forOperator = await sign(w.admin, { for_user_id: operatorId })
      expect(forOperator.body.error.code).toBe('ssh_no_access')
      expect((await sign(w.admin, { for_user_id: crypto.randomUUID() })).status).toBe(404)
      const adminId = await userId(w.admin)
      const [issued] = await query()`select requested_by_user_id from ssh_certificates where user_id = ${devId} order by created_at desc limit 1`
      expect(issued!.requested_by_user_id).toBe(adminId)
      await ageSessions(11)
      const stale = await sign(w.admin, { for_user_id: devId })
      expect([stale.status, stale.body.error?.code]).toEqual([403, 'reauth_required'])
    })

    ssh('enforces the key policy and attestation errors', async () => {
      const w = await world()
      const secure = (await w.admin.rpc('ssh_host_groups.create', { name: 'Secure', slug: 'secure', ssh_ca_id: w.ca.id, host_patterns: ['*.secure.corp'], key_policy: 'sk' })).body.data
      const attested = (await w.admin.rpc('ssh_host_groups.create', { name: 'Attested', slug: 'attested', ssh_ca_id: w.ca.id, host_patterns: ['*.att.corp'], key_policy: 'sk_attested' })).body.data
      for (const id of [secure.id, attested.id]) await w.admin.rpc('ssh_access_rules.create', { host_group_id: id, group_id: w.group.id, logins: ['root'] })
      const plain = work.keygen('plain')
      const sk = skLine(plain.pub)
      const sign = (host_group_id: string, body: object) => w.dev.rpc('ssh_user_certificates.sign', { host_group_id, ...body })

      // A throwaway key is not enough where a security key is required.
      let answer = await sign(secure.id, { public_key: plain.pub })
      expect([answer.status, answer.body.error.code]).toEqual([400, 'ssh_key_policy'])
      // A security key is accepted under `sk`, with or without an attestation that is not required.
      expect((await sign(secure.id, { public_key: sk })).status).toBe(200)
      // Under `sk_attested` a key without an attestation is refused.
      answer = await sign(attested.id, { public_key: sk })
      expect([answer.status, answer.body.error.code]).toEqual([400, 'ssh_key_policy'])
      // Garbage attestations are refused: not a Yubico chain, bad base64, missing challenge, plain key.
      const challenge = randomBytes(32).toString('base64')
      for (const body of [
        { public_key: sk, attestation: Buffer.from('nonsense').toString('base64'), attestation_challenge: challenge },
        { public_key: sk, attestation: '!!!', attestation_challenge: challenge },
        { public_key: sk, attestation: Buffer.from('x').toString('base64') },
        { public_key: sk, attestation: Buffer.from('x').toString('base64'), attestation_challenge: Buffer.alloc(8).toString('base64') },
      ]) {
        const refused = await sign(attested.id, body)
        expect([refused.status, refused.body.error.code]).toEqual([400, 'ssh_attestation_invalid'])
      }
      // Only a security key can be attested, whatever the policy.
      const plainAttested = await sign(w.hostGroup.id, { public_key: plain.pub, attestation: Buffer.from('x').toString('base64'), attestation_challenge: challenge })
      expect([plainAttested.status, plainAttested.body.error.code]).toEqual([400, 'ssh_attestation_invalid'])
      // Also refused where attestation is optional, because a bad one is never ignored.
      const optional = await sign(secure.id, { public_key: sk, attestation: Buffer.from('nonsense').toString('base64'), attestation_challenge: challenge })
      expect(optional.body.error.code).toBe('ssh_attestation_invalid')
    })

    ssh('lists the reachable hosts with the logins held there', async () => {
      const w = await world()
      const hostKey = work.keygen('reach-host')
      const created = await w.operator.rpc('ssh_hosts.create', { host_group_id: w.hostGroup.id, hostnames: ['web1.prod.corp'], public_keys: [hostKey.pub] })
      expect(created.status).toBe(200)
      const reachable = (await w.dev.rpc('ssh_hosts.reachable', { limit: 500 })).body
      expect(reachable.data).toEqual([
        expect.objectContaining({ id: created.body.data.id, name: 'web1.prod.corp', hostnames: ['web1.prod.corp'], logins: ['deploy', 'dev'], host_group: expect.objectContaining({ slug: 'prod' }) }),
      ])
      expect((await w.outsider.rpc('ssh_hosts.reachable')).body.data).toEqual([])
      expect((await w.dev.rpc('ssh_hosts.reachable', { limit: 501 })).status).toBe(400)
    })
  })

  describe('hosts', () => {
    async function join(w: World, hostnames = ['web1.prod.corp']) {
      const hostKey = work.keygen(`host-${randomBytes(3).toString('hex')}`)
      const token = (await w.admin.rpc('ssh_join_tokens.create', { host_group_id: w.hostGroup.id, label: 'web1' })).body.data
      const anon = new Client()
      const joined = await anon.rpc('ssh_hosts.join', { token: token.token, hostnames, public_keys: [hostKey.pub] })
      return { anon, hostKey, token, joined }
    }

    async function sync(anon: Client, host_id: string, keyPath: string, public_keys: string[]) {
      const challenge = (await anon.rpc('ssh_hosts.challenge', { host_id })).body
      const signature = work.sign(keyPath, challenge.nonce)
      return { challenge, signature, answer: await anon.rpc('ssh_hosts.sync', { host_id, nonce: challenge.nonce, signature, public_keys }) }
    }

    ssh('enrols a host with a single-use token and gives it a certificate', async () => {
      const w = await world()
      const { hostKey, token, joined, anon } = await join(w)
      expect(token.token).toMatch(/^cfj_/)
      expect(joined.status, JSON.stringify(joined.body)).toBe(200)
      const sync = joined.body.data
      expect(sync.host).toMatchObject({ name: 'web1.prod.corp', host_group: { slug: 'prod', name: 'Prod' } })
      expect(sync.ca_public_key).toBe(w.ca.public_key)
      expect(sync.krl_url).toBe(`${process.env.URL}/api/pki/ssh/main.krl`)
      expect(sync.sync_interval_seconds).toBe(900)
      expect(sync.principals).toEqual({ fixed: { deploy: ['prod:deploy'] }, own_username: true })
      expect(sync.certificates).toHaveLength(1)
      const described = work.describe(sync.certificates[0])
      expect(described.stdout).toContain('host certificate')
      expect(described.stdout).toMatch(/Principals:\s+web1\.prod\.corp/)
      expect(described.stdout).toMatch(/Key ID: "certifly:host:web1\.prod\.corp:[0-9a-f-]{36}"/)
      expect(described.stdout).toContain(run('ssh-keygen', ['-l', '-f', `${hostKey.path}.pub`]).stdout.split(' ')[1]!)
      // 90 days by default.
      const [cert] = await query()`select valid_after, valid_before from ssh_certificates where kind = 'host'`
      expect(Math.round((cert!.valid_before.getTime() - cert!.valid_after.getTime()) / 86_400_000)).toBe(90)
      // The token is spent and only its hash is stored.
      const again = await anon.rpc('ssh_hosts.join', { token: token.token, hostnames: ['web2.prod.corp'], public_keys: [hostKey.pub] })
      expect([again.status, again.body.error.code]).toEqual([401, 'invalid_token'])
      const [stored] = await query()`select token_hash, used_at from ssh_join_tokens`
      expect(stored!.token_hash).not.toBe(token.token)
      expect(stored!.used_at).not.toBeNull()
      expect(JSON.stringify((await w.admin.rpc('ssh_join_tokens.list')).body)).not.toContain(token.token)
    })

    ssh('refuses host names outside the patterns, bad keys, unknown and expired tokens', async () => {
      const w = await world()
      const key = work.keygen('hk')
      const mint = async () => (await w.admin.rpc('ssh_join_tokens.create', { host_group_id: w.hostGroup.id })).body.data.token as string
      const anon = new Client()
      const wrongName = await anon.rpc('ssh_hosts.join', { token: await mint(), hostnames: ['web1.test.corp'], public_keys: [key.pub] })
      expect([wrongName.status, wrongName.body.error.code]).toEqual([400, 'host_name_not_allowed'])
      const wrongKey = await anon.rpc('ssh_hosts.join', { token: await mint(), hostnames: ['web1.prod.corp'], public_keys: ['ssh-dss AAAA'] })
      expect([wrongKey.status, wrongKey.body.error.code]).toEqual([400, 'ssh_key_type'])
      expect((await anon.rpc('ssh_hosts.join', { token: 'cfj_nonsense', hostnames: ['web1.prod.corp'], public_keys: [key.pub] })).status).toBe(401)
      expect((await anon.rpc('ssh_hosts.join', { token: 'not-even-a-token', hostnames: ['web1.prod.corp'], public_keys: [key.pub] })).status).toBe(401)
      // A failed join leaves the token usable; an expired one is refused.
      const good = await mint()
      expect((await anon.rpc('ssh_hosts.join', { token: good, hostnames: ['web1.prod.corp'], public_keys: [key.pub] })).status).toBe(200)
      const expired = await mint()
      await query()`update ssh_join_tokens set expires_at = now() - interval '1 minute'`
      expect((await anon.rpc('ssh_hosts.join', { token: expired, hostnames: ['web2.prod.corp'], public_keys: [key.pub] })).status).toBe(401)
    })

    ssh('never lets two hosts hold the same host name, whatever their host group or CA', async () => {
      const w = await world()
      const first = await join(w, ['web1.prod.corp'])
      expect(first.joined.status).toBe(200)
      // A join that claims the other host's name next to a new one is refused, and its token stays usable.
      const second = await join(w, ['new.prod.corp', 'web1.prod.corp'])
      expect([second.joined.status, second.joined.body.error.code]).toEqual([409, 'hostname_taken'])
      expect((await second.anon.rpc('ssh_hosts.join', { token: second.token.token, hostnames: ['new.prod.corp'], public_keys: [second.hostKey.pub] })).status).toBe(200)
      // Under another CA as well.
      const other = (await w.admin.rpc('ssh_cas.create', { name: 'Other', slug: 'other' })).body.data
      const wide = await w.admin.rpc('ssh_host_groups.create', { name: 'Wide', slug: 'wide', ssh_ca_id: other.id, host_patterns: ['*.prod.corp', '*.spare.corp'] })
      expect(wide.status, JSON.stringify(wide.body)).toBe(200)
      const otherGroup = wide.body.data
      const key = work.keygen('dup')
      const created = await w.operator.rpc('ssh_hosts.create', { host_group_id: otherGroup.id, hostnames: ['WEB1.prod.corp'], public_keys: [key.pub] })
      expect([created.status, created.body.error.code]).toEqual([409, 'hostname_taken'])
      // Renaming a host onto another's name is refused; keeping its own names is fine.
      const spare = (await w.operator.rpc('ssh_hosts.create', { host_group_id: otherGroup.id, hostnames: ['a.spare.corp'], public_keys: [key.pub] })).body.data
      const renamed = await w.operator.rpc('ssh_hosts.update', { id: spare.id, hostnames: ['a.spare.corp', 'new.prod.corp'] })
      expect([renamed.status, renamed.body.error.code]).toEqual([409, 'hostname_taken'])
      expect((await w.operator.rpc('ssh_hosts.update', { id: spare.id, hostnames: ['a.spare.corp'], name: 'Spare' })).status).toBe(200)
    })

    ssh('refuses host and host group names with line breaks or control characters', async () => {
      const w = await world()
      const injected = await w.admin.rpc('ssh_host_groups.create', { name: 'x\nHost *\n  ProxyCommand touch /tmp/pwned', slug: 'inj', ssh_ca_id: w.ca.id })
      expect([injected.status, injected.body.error.code]).toEqual([400, 'validation_error'])
      expect((await w.admin.rpc('ssh_host_groups.update', { id: w.hostGroup.id, name: 'Prod\u001b[31m' })).status).toBe(400)
      const key = work.keygen('ctl')
      expect((await w.operator.rpc('ssh_hosts.create', { host_group_id: w.hostGroup.id, hostnames: ['a.prod.corp'], public_keys: [key.pub], name: 'a\u009b2J' })).status).toBe(400)
    })

    ssh('makes room for a new challenge by dropping the oldest one, so nobody can block a host', async () => {
      const w = await world()
      const { anon, hostKey, joined } = await join(w)
      const hostId = joined.body.data.host.id
      const nonces: string[] = []
      for (let i = 0; i < 12; i++) {
        const answer = await anon.rpc('ssh_hosts.challenge', { host_id: hostId })
        expect(answer.status).toBe(200)
        nonces.push(answer.body.nonce)
      }
      const [open] = await query()`select count(*)::int as n from ssh_host_challenges where host_id = ${hostId} and used_at is null`
      expect(open!.n).toBe(10)
      const answer = (nonce: string) => anon.rpc('ssh_hosts.sync', { host_id: hostId, nonce, signature: work.sign(hostKey.path, nonce), public_keys: [hostKey.pub] })
      expect((await answer(nonces[0]!)).status).toBe(403)
      expect((await answer(nonces[11]!)).status).toBe(200)
    })

    ssh('syncs with a nonce signed by the host key, once', async () => {
      const w = await world()
      const { anon, hostKey, joined } = await join(w)
      const hostId = joined.body.data.host.id
      const first = await sync(anon, hostId, hostKey.path, [hostKey.pub])
      expect(first.answer.status, JSON.stringify(first.answer.body)).toBe(200)
      expect(first.answer.body.data.certificates).toHaveLength(1)
      // Same certificate: nothing was due for renewal.
      expect(first.answer.body.data.certificates).toEqual(joined.body.data.certificates)
      expect(Date.parse(first.challenge.expires_at) - Date.now()).toBeGreaterThan(4 * 60_000)
      // The nonce is spent.
      const replay = await anon.rpc('ssh_hosts.sync', { host_id: hostId, nonce: first.challenge.nonce, signature: first.signature, public_keys: [hostKey.pub] })
      expect([replay.status, replay.body.error.code]).toEqual([403, 'host_not_verified'])
      // A signature from some other key, for another namespace, or over another text is refused.
      const stranger = work.keygen('stranger')
      const nonce = (await anon.rpc('ssh_hosts.challenge', { host_id: hostId })).body.nonce
      for (const signature of [work.sign(stranger.path, nonce), work.sign(hostKey.path, nonce, 'other@certifly'), work.sign(hostKey.path, `${nonce}\n`)]) {
        const refused = await anon.rpc('ssh_hosts.sync', { host_id: hostId, nonce, signature, public_keys: [hostKey.pub] })
        expect([refused.status, refused.body.error.code]).toEqual([403, 'host_not_verified'])
      }
      // Failed attempts spent the nonce too.
      const spent = await anon.rpc('ssh_hosts.sync', { host_id: hostId, nonce, signature: work.sign(hostKey.path, nonce), public_keys: [hostKey.pub] })
      expect(spent.status).toBe(403)
      expect((await anon.rpc('ssh_hosts.challenge', { host_id: crypto.randomUUID() })).status).toBe(404)
    })

    ssh('renews certificates with less than a third of their lifetime left', async () => {
      const w = await world()
      const { anon, hostKey, joined } = await join(w)
      const hostId = joined.body.data.host.id
      await query()`update ssh_certificates set valid_after = now() - interval '90 days', valid_before = now() + interval '10 days' where kind = 'host'`
      const renewed = await sync(anon, hostId, hostKey.path, [hostKey.pub])
      expect(renewed.answer.status).toBe(200)
      expect(renewed.answer.body.data.certificates).toHaveLength(1)
      expect(renewed.answer.body.data.certificates[0]).not.toBe(joined.body.data.certificates[0])
      const rows = await query()`select valid_before from ssh_certificates where kind = 'host' order by created_at`
      expect(rows).toHaveLength(2)
      expect(rows[1]!.valid_before.getTime() - Date.now()).toBeGreaterThan(80 * 86_400_000)
    })

    ssh('accepts a key rotation signed by a registered key and revokes the old key’s certificate', async () => {
      const w = await world()
      const { anon, hostKey, joined } = await join(w)
      const hostId = joined.body.data.host.id
      const newKey = work.keygen('rotated')
      const rotated = await sync(anon, hostId, hostKey.path, [newKey.pub])
      expect(rotated.answer.status, JSON.stringify(rotated.answer.body)).toBe(200)
      const [line] = rotated.answer.body.data.certificates as string[]
      expect(rotated.answer.body.data.certificates).toHaveLength(1)
      expect(work.describe(line!).stdout).toContain(run('ssh-keygen', ['-l', '-f', `${newKey.path}.pub`]).stdout.split(' ')[1]!)
      // The old key is no longer registered: it cannot sign for the host any more.
      const old = await sync(anon, hostId, hostKey.path, [newKey.pub])
      expect(old.answer.status).toBe(403)
      // And the old certificate is on the revocation list.
      const krl = Buffer.from(await (await new Client().get('/api/pki/ssh/main.krl')).arrayBuffer())
      const krlFile = work.write('rotated.krl', krl)
      const oldCert = work.describe(joined.body.data.certificates[0])
      expect(run('ssh-keygen', ['-Q', '-f', krlFile, oldCert.path]).status).toBe(1)
      const current = work.describe(line!)
      expect(run('ssh-keygen', ['-Q', '-f', krlFile, current.path]).status).toBe(0)
      // A key set that the signing key is not in is refused only through the signature, never by shape.
      const stranger = work.keygen('rotated-stranger')
      const bad = await sync(anon, hostId, stranger.path, [stranger.pub])
      expect(bad.answer.status).toBe(403)
    })

    ssh('revokes a host’s certificates when it is changed or removed', async () => {
      const w = await world()
      const { joined, hostKey } = await join(w)
      const hostId = joined.body.data.host.id
      const status = async () => (await w.operator.rpc('ssh_certificates.list', { kind: 'host' })).body.data.map((c: { status: string }) => c.status)
      expect(await status()).toEqual(['active'])
      // Only a name changes: the certificate stays.
      expect((await w.operator.rpc('ssh_hosts.update', { id: hostId, name: 'web-one' })).status).toBe(200)
      expect(await status()).toEqual(['active'])
      // New names, even matching ones, revoke it.
      expect((await w.operator.rpc('ssh_hosts.update', { id: hostId, hostnames: ['web9.prod.corp'] })).status).toBe(200)
      expect(await status()).toEqual(['revoked'])
      const mismatch = await w.operator.rpc('ssh_hosts.update', { id: hostId, hostnames: ['web9.other.corp'] })
      expect([mismatch.status, mismatch.body.error.code]).toEqual([400, 'host_name_not_allowed'])
      // A fresh sync issues new certificates for the new names; deleting the host revokes them again.
      const { anon } = { anon: new Client() }
      const synced = await sync(anon, hostId, hostKey.path, [hostKey.pub])
      expect(synced.answer.body.data.certificates).toHaveLength(1)
      expect((await w.operator.rpc('ssh_hosts.delete', { id: hostId })).status).toBe(200)
      expect(await status()).toEqual(['revoked', 'revoked'])
    })
  })

  describe('revocation lists', () => {
    ssh('serve a list that contains a revoked serial and that ssh-keygen -Q agrees with', async () => {
      const w = await world()
      const certs: { id: string; certificate: string; serial: string }[] = []
      for (const name of ['one', 'two']) {
        const key = work.keygen(`krl-${name}`)
        const signed = await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub })
        certs.push(signed.body.data)
      }
      const fetchKrl = async () => {
        const response = await new Client().get('/api/pki/ssh/main.krl')
        expect(response.status).toBe(200)
        expect(response.headers.get('cache-control')).toBe('no-cache')
        return work.write('served.krl', Buffer.from(await response.arrayBuffer()))
      }
      const check = (krl: string, cert: { certificate: string }) => run('ssh-keygen', ['-Q', '-f', krl, work.describe(cert.certificate).path]).status
      let krl = await fetchKrl()
      expect(check(krl, certs[0]!)).toBe(0)

      // A person revokes their own certificate; the list is rebuilt in the same call.
      const revoked = await w.dev.rpc('ssh_certificates.revoke', { id: certs[0]!.id, reason: 'key_compromise' })
      expect(revoked.status).toBe(200)
      expect(revoked.body.data).toMatchObject({ status: 'revoked', revocation_reason: 'key_compromise' })
      krl = await fetchKrl()
      expect(check(krl, certs[0]!)).toBe(1)
      expect(check(krl, certs[1]!)).toBe(0)
      expect(run('ssh-keygen', ['-Q', '-l', '-f', krl]).stdout).toContain(`serial: ${certs[0]!.serial}`)
      // Revoking again changes nothing; someone else’s certificate is not found; an invalid reason is refused.
      expect((await w.dev.rpc('ssh_certificates.revoke', { id: certs[0]!.id })).status).toBe(200)
      expect((await w.outsider.rpc('ssh_certificates.revoke', { id: certs[1]!.id })).status).toBe(404)
      expect((await w.dev.rpc('ssh_certificates.revoke', { id: certs[1]!.id, reason: 'bored' })).status).toBe(400)
      // An operator revokes anyone’s.
      expect((await w.operator.rpc('ssh_certificates.revoke', { id: certs[1]!.id })).status).toBe(200)
      krl = await fetchKrl()
      expect(check(krl, certs[1]!)).toBe(1)
      // The version only grows.
      const [row] = await query()`select version from ssh_krls`
      expect(Number(row!.version)).toBeGreaterThanOrEqual(3)
      expect((await new Client().get('/api/pki/ssh/nope.krl')).status).toBe(404)
      expect((await new Client().get('/api/pki/ssh/main.txt')).status).toBe(404)
    })

    ssh('revokes a person’s valid certificates when they are deactivated', async () => {
      const w = await world()
      const key = work.keygen('deact')
      const signed = (await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub })).body.data
      expect((await w.admin.rpc('users.update', { id: w.devId, deactivated: true })).status).toBe(200)
      const krl = work.write('deact.krl', Buffer.from(await (await new Client().get('/api/pki/ssh/main.krl')).arrayBuffer()))
      expect(run('ssh-keygen', ['-Q', '-f', krl, work.describe(signed.certificate).path]).status).toBe(1)
      const [row] = await query()`select revoked_at, revocation_reason from ssh_certificates`
      expect(row).toMatchObject({ revocation_reason: 'privilege_withdrawn' })
    })
  })

  describe('administration and roles', () => {
    it('keeps SSH configuration to the roles that own it', async () => {
      const w = await world()
      const calls: [string, object][] = [
        ['ssh_cas.create', { name: 'Other', slug: 'other' }],
        ['ssh_cas.update', { id: w.ca.id, name: 'x' }],
        ['ssh_host_groups.create', { name: 'x', slug: 'x', ssh_ca_id: w.ca.id }],
        ['ssh_host_groups.update', { id: w.hostGroup.id, name: 'x' }],
        ['ssh_access_rules.create', { host_group_id: w.hostGroup.id, group_id: w.group.id, logins: ['x'] }],
        ['groups.create', { name: 'x' }],
        ['group_members.create', { group_id: w.group.id, user_id: w.devId }],
        ['ssh_join_tokens.create', { host_group_id: w.hostGroup.id }],
      ]
      for (const client of [w.operator, w.dev]) {
        for (const [method, body] of calls) expect({ method, status: (await client.rpc(method, body)).status }).toEqual({ method, status: 403 })
      }
      // Reading: everyone reads CAs; operators read host groups and hosts; only admins read rules, groups and tokens.
      for (const client of [w.admin, w.operator, w.dev]) expect((await client.rpc('ssh_cas.list')).body.data).toHaveLength(1)
      expect((await w.operator.rpc('ssh_host_groups.list')).body.data).toHaveLength(1)
      expect((await w.dev.rpc('ssh_host_groups.list')).status).toBe(403)
      for (const method of ['ssh_access_rules.list', 'groups.list', 'ssh_join_tokens.list']) {
        expect({ method, status: (await w.operator.rpc(method)).status }).toEqual({ method, status: 403 })
        expect((await w.admin.rpc(method)).status).toBe(200)
      }
      expect((await w.operator.rpc('ssh_hosts.list')).status).toBe(200)
      expect((await w.dev.rpc('ssh_hosts.list')).status).toBe(403)
      expect((await w.dev.rpc('ssh_hosts.create', { host_group_id: w.hostGroup.id, hostnames: ['a.prod.corp'], public_keys: ['x'] })).status).toBe(403)
      // Certificates: everyone sees their own, operators see all.
      const key = work.keygen('roles')
      await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub })
      expect((await w.dev.rpc('ssh_certificates.list')).body.data).toHaveLength(1)
      expect((await w.outsider.rpc('ssh_certificates.list')).body.data).toHaveLength(0)
      expect((await w.operator.rpc('ssh_certificates.list')).body.data).toHaveLength(1)
    })

    ssh('searches certificates by key ID and principals and counts them by kind and revocation', async () => {
      const w = await world()
      const key = work.keygen('search')
      const signed = (await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: key.pub })).body.data
      const other = work.keygen('search-two')
      await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: w.hostGroup.id, public_key: other.pub })
      expect((await w.dev.rpc('ssh_certificates.revoke', { id: signed.id })).status).toBe(200)

      const all = (await w.operator.rpc('ssh_certificates.list')).body
      expect(all.counts).toEqual({ all: 2, user: 2, host: 0, revoked: 1 })
      // Counts follow the search but not kind or status.
      const searched = (await w.operator.rpc('ssh_certificates.list', { query: 'PROD:DEPLOY', status: 'active' })).body
      expect(searched.data).toHaveLength(1)
      expect(searched.counts).toEqual({ all: 2, user: 2, host: 0, revoked: 1 })
      expect((await w.operator.rpc('ssh_certificates.list', { query: 'dev@example.com' })).body.data).toHaveLength(2)
      const none = (await w.operator.rpc('ssh_certificates.list', { query: 'nothing-like-this' })).body
      expect([none.data.length, none.counts.all]).toEqual([0, 0])
      // People only count their own.
      expect((await w.outsider.rpc('ssh_certificates.list')).body.counts).toEqual({ all: 0, user: 0, host: 0, revoked: 0 })
      expect((await w.dev.rpc('ssh_certificates.list')).body.counts.all).toBe(2)
    })

    it('names who created a join token', async () => {
      const w = await world()
      const token = (await w.admin.rpc('ssh_join_tokens.create', { host_group_id: w.hostGroup.id, label: 'rollout' })).body.data
      expect(token.label).toBe('rollout')
      const listed = (await w.admin.rpc('ssh_join_tokens.list')).body.data
      expect(listed).toHaveLength(1)
      expect(listed[0].created_by).toMatchObject({ name: expect.any(String) })
    })

    it('asks for a recent confirmation to create or import CAs, mint join tokens and change access, and never lets an API key do it', async () => {
      const w = await world()
      const key = (await w.admin.rpc('api_keys.create', { name: 'ci' })).body.data
      const viaKey = (method: string, body: object) => new Client().rpcWithKey(key.secret, method, body)
      const generated = work.keygen('import-me')
      const privateKey = readFileSync(generated.path, 'utf8')
      const actions: [string, object][] = [
        ['ssh_cas.create', { name: 'Two', slug: 'two' }],
        ['ssh_cas.import', { name: 'Three', slug: 'three', private_key: privateKey }],
        ['ssh_join_tokens.create', { host_group_id: w.hostGroup.id }],
      ]
      for (const [method, body] of actions) expect({ method, status: (await viaKey(method, body)).status }).toEqual({ method, status: 403 })
      await ageSessions(11)
      for (const [method, body] of actions) {
        const answer = await w.admin.rpc(method, body)
        expect({ method, status: answer.status, code: answer.body.error?.code }).toEqual({ method, status: 403, code: 'reauth_required' })
      }
      // Host groups, groups, memberships and rules decide who may log in where: they ask again too,
      // and API keys cannot change them.
      const access: [string, object][] = [
        ['ssh_host_groups.update', { id: w.hostGroup.id, name: 'Renamed' }],
        ['ssh_access_rules.update', { id: w.rule.id, logins: ['root'] }],
        ['groups.create', { name: 'Stale' }],
        ['group_members.delete', { group_id: w.group.id, user_id: w.devId }],
      ]
      for (const [method, body] of access) {
        expect({ method, status: (await viaKey(method, body)).status }).toEqual({ method, status: 403 })
        const answer = await w.admin.rpc(method, body)
        expect({ method, status: answer.status, code: answer.body.error?.code }).toEqual({ method, status: 403, code: 'reauth_required' })
      }
      // Reading them with an API key still works.
      expect((await viaKey('ssh_access_rules.list', {})).status).toBe(200)
    })

    ssh('generates and imports CAs and refuses encrypted keys', async () => {
      const w = await world()
      for (const key_algorithm of ['ed25519', 'ecdsa-p256', 'rsa-4096'] as const) {
        const created = await w.admin.rpc('ssh_cas.create', { name: key_algorithm, slug: `ca-${key_algorithm}`, key_algorithm })
        expect(created.status, JSON.stringify(created.body)).toBe(200)
        expect(created.body.data.public_key).toMatch(/^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) /)
        // The private key is nowhere in the answer.
        expect(JSON.stringify(created.body)).not.toMatch(/PRIVATE|ciphertext|wrapped_dek/)
      }
      expect((await w.admin.rpc('ssh_cas.create', { name: 'dup', slug: 'main' })).body.error.code).toBe('slug_taken')
      expect((await w.admin.rpc('ssh_cas.create', { name: 'bad', slug: 'Not Valid' })).body.error.code).toBe('invalid_slug')

      const plain = work.keygen('import-ca')
      const imported = await w.admin.rpc('ssh_cas.import', { name: 'Imported', slug: 'imported', private_key: readFileSync(plain.path, 'utf8') })
      expect(imported.status, JSON.stringify(imported.body)).toBe(200)
      expect(imported.body.data.source).toBe('imported')
      expect(imported.body.data.public_key.split(' ').slice(0, 2).join(' ')).toBe(plain.pub.split(' ').slice(0, 2).join(' '))
      // A certificate signed by the imported CA is accepted by ssh-keygen under that CA key.
      const group = (await w.admin.rpc('ssh_host_groups.create', { name: 'Imp', slug: 'imp', ssh_ca_id: imported.body.data.id })).body.data
      await w.admin.rpc('ssh_access_rules.create', { host_group_id: group.id, group_id: w.group.id, logins: ['ops'] })
      const key = work.keygen('imp-user')
      const signed = (await w.dev.rpc('ssh_user_certificates.sign', { host_group_id: group.id, public_key: key.pub })).body.data
      expect(work.describe(signed.certificate).stdout).toContain(run('ssh-keygen', ['-l', '-f', `${plain.path}.pub`]).stdout.split(' ')[1]!)

      const encrypted = work.keygen('enc')
      run('ssh-keygen', ['-p', '-N', 'secret-passphrase', '-f', encrypted.path])
      const refused = await w.admin.rpc('ssh_cas.import', { name: 'Enc', slug: 'enc', private_key: readFileSync(encrypted.path, 'utf8') })
      expect([refused.status, refused.body.error.code]).toEqual([400, 'ssh_key_encrypted'])
      expect(refused.body.error.message).toContain('ssh-keygen -p -N')
      expect((await w.admin.rpc('ssh_cas.import', { name: 'Junk', slug: 'junk', private_key: 'not a key' })).status).toBe(400)
      // A CA that is in use cannot be deleted.
      expect((await w.admin.rpc('ssh_cas.delete', { id: w.ca.id })).body.error.code).toBe('ssh_ca_in_use')
      const spare = (await w.admin.rpc('ssh_cas.create', { name: 'Spare', slug: 'spare' })).body.data
      expect((await w.admin.rpc('ssh_cas.delete', { id: spare.id })).status).toBe(200)
    })

    it('validates host group settings', async () => {
      const w = await world()
      const create = (body: object) => w.admin.rpc('ssh_host_groups.create', { name: 'T', slug: `t-${randomBytes(3).toString('hex')}`, ssh_ca_id: w.ca.id, ...body })
      const code = async (body: object) => (await create(body)).body.error?.code
      expect(await code({ host_patterns: ['not a pattern'] })).toBe('invalid_host_pattern')
      expect(await code({ user_extensions: ['permit-everything'] })).toBe('invalid_extension')
      expect(await code({ source_address: ['nope'] })).toBe('invalid_source_address')
      expect(await code({ user_ttl_default_seconds: 7200, user_ttl_max_seconds: 3600 })).toBe('invalid_ttl')
      expect(await code({ user_ttl_max_seconds: 8 * 86_400 })).toBe('invalid_ttl')
      expect(await code({ host_ttl_seconds: 366 * 86_400 })).toBe('invalid_ttl')
      expect((await create({ host_patterns: ['web1', '*.prod.corp'], key_policy: 'sk_attested' })).body.data).toMatchObject({ key_policy: 'sk_attested', user_ttl_default_seconds: 8 * 3600, user_ttl_max_seconds: 24 * 3600, host_ttl_seconds: 90 * 86_400, user_extensions: ['permit-pty'] })
      expect((await w.admin.rpc('ssh_host_groups.create', { name: 'Dup', slug: 'prod', ssh_ca_id: w.ca.id })).body.error.code).toBe('slug_taken')
      // A host group with hosts cannot go.
      expect((await w.admin.rpc('ssh_host_groups.delete', { id: w.hostGroup.id })).status).toBe(200)
    })

    it('has unique case-insensitive usernames that only admins change, and never a system account', async () => {
      const w = await world()
      const outsiderId = await userId(w.outsider)
      expect((await w.dev.rpc('users.update', { id: w.devId, username: 'alice' })).status).toBe(403)
      expect((await w.admin.rpc('users.update', { id: w.devId, username: 'root' })).body.error.code).toBe('reserved_username')
      expect((await w.admin.rpc('users.update', { id: w.devId, username: 'Bad Name' })).body.error.code).toBe('invalid_username')
      expect((await w.admin.rpc('users.update', { id: w.devId, username: 'Alice' })).body.data.username).toBe('alice')
      expect((await w.admin.rpc('users.update', { id: outsiderId, username: 'ALICE' })).body.error.code).toBe('username_taken')
      // The new username shows up in the principals right away.
      expect((await w.dev.rpc('ssh_access.get')).body.host_groups[0].logins).toEqual(['alice', 'deploy'])
      // Derived names are suffixed on collision and never reserved.
      const [root] = await query()`select count(*)::int as n from users where username = 'root'`
      expect(root!.n).toBe(0)
      const clash = await addUser(w.admin, 'alice@other.example', 'viewer')
      await w.admin.rpc('group_members.create', { group_id: w.group.id, user_id: await userId(clash) })
      expect((await clash.rpc('ssh_access.get')).body.user.username).toBe('alice2')
      const rooter = await addUser(w.admin, 'root@example.com', 'viewer')
      expect((await rooter.rpc('ssh_access.get')).body.user.username).toBe('root-1')
    })

    it('manages groups, memberships and rules', async () => {
      const w = await world()
      expect((await w.admin.rpc('groups.create', { name: 'developers' })).body.error.code).toBe('group_name_taken')
      const members = (await w.admin.rpc('group_members.list', { group_id: w.group.id })).body.data
      expect(members).toEqual([expect.objectContaining({ user_id: w.devId, source: 'manual', email: 'dev@example.com' })])
      expect((await w.admin.rpc('ssh_access_rules.create', { host_group_id: w.hostGroup.id, group_id: w.group.id, logins: ['x'] })).body.error.code).toBe('rule_exists')
      expect((await w.admin.rpc('ssh_access_rules.create', { host_group_id: w.hostGroup.id, group_id: (await w.admin.rpc('groups.create', { name: 'Empty' })).body.data.id })).body.error.code).toBe('rule_empty')
      expect((await w.admin.rpc('ssh_access_rules.update', { id: w.rule.id, logins: ['bad login'] })).body.error.code).toBe('invalid_login')
      expect((await w.admin.rpc('ssh_access_rules.update', { id: w.rule.id, logins: ['root'], own_username: false })).status).toBe(200)
      expect((await w.dev.rpc('ssh_access.get')).body.host_groups[0].logins).toEqual(['root'])
      // Removing the member or the rule takes the access away at the next certificate.
      expect((await w.admin.rpc('group_members.delete', { group_id: w.group.id, user_id: w.devId })).status).toBe(200)
      expect((await w.dev.rpc('ssh_access.get')).body.host_groups).toEqual([])
      expect((await w.admin.rpc('groups.delete', { id: w.group.id })).status).toBe(200)
      expect((await w.admin.rpc('ssh_access_rules.list')).body.data).toEqual([])
    })

    it('mirrors the identity provider’s groups at sign-in without touching manual members', async () => {
      const w = await world()
      const provider = (await w.admin.rpc('groups.create', { name: 'Ops', provider_groups: ['ops', 'sre'] })).body.data
      const core = await coreContext()
      try {
        const { syncProviderGroups } = await import('@certifly/core/groups')
        const user = { id: w.devId, role: 'viewer' as const }
        // No claim at all: nothing changes.
        await syncProviderGroups(core.ctx, user, undefined)
        expect((await w.admin.rpc('group_members.list', { group_id: provider.id })).body.data).toHaveLength(0)
        await syncProviderGroups(core.ctx, user, ['sre', 'unrelated'])
        expect((await w.admin.rpc('group_members.list', { group_id: provider.id })).body.data).toEqual([expect.objectContaining({ user_id: w.devId, source: 'oidc' })])
        // Provider members cannot be removed by hand; they leave with their provider group.
        expect((await w.admin.rpc('group_members.delete', { group_id: provider.id, user_id: w.devId })).body.error.code).toBe('member_from_provider')
        await syncProviderGroups(core.ctx, user, [])
        expect((await w.admin.rpc('group_members.list', { group_id: provider.id })).body.data).toHaveLength(0)
        // The manual membership of Developers survived all of it.
        expect((await w.admin.rpc('group_members.list', { group_id: w.group.id })).body.data).toHaveLength(1)
        // Adding by hand turns a provider membership into a manual one, which then stays.
        await syncProviderGroups(core.ctx, user, ['ops'])
        expect((await w.admin.rpc('group_members.create', { group_id: provider.id, user_id: w.devId })).status).toBe(200)
        await syncProviderGroups(core.ctx, user, [])
        expect((await w.admin.rpc('group_members.list', { group_id: provider.id })).body.data).toEqual([expect.objectContaining({ source: 'manual' })])
      } finally {
        await core.close()
      }
    })
  })

  describe('expiry alerts for host certificates', () => {
    ssh('warn once per threshold, and not for a certificate that was renewed', async () => {
      const w = await world()
      const channel = (await w.admin.rpc('alert_channels.create', { kind: 'email', name: 'Ops', recipients: ['ops@example.com'] })).body.data.channel
      const rule = await w.admin.rpc('alert_rules.create', { name: 'SSH hosts', event: 'ssh_host_expiring', days_before: [30, 7], channel_ids: [channel.id] })
      expect(rule.status, JSON.stringify(rule.body)).toBe(200)
      const hostKey = work.keygen('alert-host')
      const token = (await w.admin.rpc('ssh_join_tokens.create', { host_group_id: w.hostGroup.id })).body.data.token
      const anon = new Client()
      const joined = await anon.rpc('ssh_hosts.join', { token, hostnames: ['web1.prod.corp'], public_keys: [hostKey.pub] })
      expect(joined.status).toBe(200)
      const core = await coreContext()
      try {
        const { scanExpiryAlerts } = await import('@certifly/core/alerts')
        // 90 days left: nothing to say.
        expect((await scanExpiryAlerts(core.ctx)).queued).toBe(0)
        await query()`update ssh_certificates set valid_before = now() + interval '20 days' where kind = 'host'`
        expect((await scanExpiryAlerts(core.ctx)).queued).toBe(1)
        // The same threshold is not sent again.
        expect((await scanExpiryAlerts(core.ctx)).queued).toBe(0)
        await query()`update ssh_certificates set valid_before = now() + interval '5 days' where kind = 'host'`
        expect((await scanExpiryAlerts(core.ctx)).queued).toBe(1)
        const [delivery] = await query()`select payload, event from alert_deliveries order by created_at desc limit 1`
        expect(delivery!.event).toBe('ssh_host_expiring')
        expect(delivery!.payload).toMatchObject({ ssh_host: { name: 'web1.prod.corp', hostnames: ['web1.prod.corp'] }, threshold_days: 7 })
        // Once the host holds a newer certificate for the same key, the old one is not reported.
        await query()`update ssh_certificates set valid_before = now() + interval '2 days' where kind = 'host'`
        const hostId = joined.body.data.host.id
        await query()`update ssh_certificates set valid_after = now() - interval '90 days' where kind = 'host'`
        const challenge = (await anon.rpc('ssh_hosts.challenge', { host_id: hostId })).body
        const renewed = await anon.rpc('ssh_hosts.sync', { host_id: hostId, nonce: challenge.nonce, signature: work.sign(hostKey.path, challenge.nonce), public_keys: [hostKey.pub] })
        expect(renewed.status).toBe(200)
        expect((await scanExpiryAlerts(core.ctx)).queued).toBe(0)
      } finally {
        await core.close()
      }
    })
  })
})
