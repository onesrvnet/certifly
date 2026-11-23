import { fetch, setup } from '@nuxt/test-utils/e2e'
import { beforeEach, describe, expect, it } from 'vitest'
import { resetState, serverOptions, setupAdmin } from '../helpers'

describe('request guard', async () => {
  await setup(serverOptions)
  beforeEach(resetState)

  it('refuses API calls from another origin, also as a form post, and lets the own origin and origin-less clients through', async () => {
    const admin = await setupAdmin()
    const own = new URL(process.env.URL!).origin
    expect((await admin.rpc('groups.list', {}, { origin: own })).status).toBe(200)
    expect((await admin.rpc('groups.list')).status).toBe(200)
    for (const origin of ['https://evil.example', 'null', `${own}9`]) {
      const refused = await admin.rpc('groups.list', {}, { origin })
      expect({ origin, status: refused.status, code: refused.body.error?.code }).toEqual({ origin, status: 403, code: 'cross_origin' })
    }
    // A plain HTML form on a sibling subdomain would send this, with the session cookie.
    const form = await fetch('/api/v2/groups/create', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://sibling.example', cookie: admin.cookieHeader() },
      body: 'name=Pwned',
    })
    expect(form.status).toBe(403)
    expect((await admin.rpc('groups.list')).body.data).toEqual([])
  })

  it('refuses bodies over 1 MiB, declared or streamed', async () => {
    const admin = await setupAdmin()
    const big = JSON.stringify({ name: 'x'.repeat(1024 * 1024) })
    const declared = await fetch('/api/v2/groups/create', { method: 'POST', headers: { 'content-type': 'application/json' }, body: big })
    expect(declared.status).toBe(413)
    const chunks = new ReadableStream({
      start(controller) {
        for (let i = 0; i < 20; i++) controller.enqueue(new TextEncoder().encode('x'.repeat(64 * 1024)))
        controller.close()
      },
    })
    const streamed = await fetch('/api/v2/groups/create', { method: 'POST', headers: { 'content-type': 'application/json' }, body: chunks, duplex: 'half' } as RequestInit)
    expect(streamed.status).toBe(413)
    // An ordinary body still arrives whole.
    expect((await admin.rpc('groups.create', { name: 'Fine' })).status).toBe(200)
  })
})
