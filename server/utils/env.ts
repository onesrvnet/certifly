import { readFileSync } from 'node:fs'
import { parseMasterKey } from '@certifly/keyvault'
import { z } from 'zod'

/** Treat empty variables (e.g. `SMTP_URL=` from the sample file) as unset. */
const optional = <T extends z.ZodType>(type: T) => z.preprocess((v) => (v === '' ? undefined : v), type.optional())
const flag = z.preprocess((v) => v === 'true' || v === '1', z.boolean()).default(false)

export const SERVICE_NAMES = ['web', 'worker', 'cron'] as const
export type ServiceName = (typeof SERVICE_NAMES)[number]

/**
 * Checks a master key the way the keyvault will read it: 32 bytes as hex or base64, and not
 * the session secret in any encoding. The decoded bytes are wiped straight away.
 */
function masterKeyProblem(value: string, session_secret: string): string | null {
  try {
    parseMasterKey(value, session_secret).fill(0)
    return null
  } catch (error) {
    return (error as Error).message
  }
}

/**
 * `CERTIFLY_MASTER_KEY_FILE` (e.g. a Docker secret) stands in for `CERTIFLY_MASTER_KEY`. Both at
 * once is refused rather than guessed.
 */
function withMasterKeyFile(source: NodeJS.ProcessEnv): { values: NodeJS.ProcessEnv; problem?: string } {
  const file = source.CERTIFLY_MASTER_KEY_FILE
  if (!file) return { values: source }
  if (source.CERTIFLY_MASTER_KEY) return { values: source, problem: 'set either CERTIFLY_MASTER_KEY or CERTIFLY_MASTER_KEY_FILE, not both' }
  try {
    return { values: { ...source, CERTIFLY_MASTER_KEY: readFileSync(file, 'utf8').trim() } }
  } catch {
    return { values: source, problem: 'the file cannot be read' }
  }
}

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    URL: z.url().default('http://localhost:3000'),
    SECRET_KEY: z.string().min(32, 'SECRET_KEY must be at least 32 characters'),
    /** Encrypts CA private keys (the keyvault's KEK). Required: without it no CA can sign. */
    CERTIFLY_MASTER_KEY: optional(z.string()),
    CERTIFLY_MASTER_KEY_FILE: optional(z.string()),
    /** Earlier master keys, comma or space separated, accepted for unwrapping until the rewrap job has moved every key. */
    CERTIFLY_MASTER_KEY_PREVIOUS: optional(z.string()),
    DATABASE_URL: z.url(),
    /** How long to wait for the database on startup before giving up (production). */
    DATABASE_WAIT_SECONDS: z.coerce.number().int().min(0).default(120),
    SERVICES: z
      .string()
      .default('web,worker,cron')
      .transform((value, ctx) => {
        const names = value.split(',').map((name) => name.trim()).filter(Boolean)
        const unknown = names.filter((name) => !(SERVICE_NAMES as readonly string[]).includes(name))
        if (unknown.length) ctx.addIssue({ code: 'custom', message: `unknown service ${unknown.join(', ')}; use ${SERVICE_NAMES.join(', ')}` })
        return new Set(names as ServiceName[])
      }),
    /** Take client IPs from the last X-Forwarded-For entry (only behind one reverse proxy that sets or appends it). */
    TRUST_PROXY: flag,
    /** Request header in which the TLS proxy passes the client certificate to EST re-enrollment. Only read with TRUST_PROXY. */
    EST_CLIENT_CERT_HEADER: z.string().trim().min(1).default('x-forwarded-tls-client-cert'),
    /** Shared secret the TLS proxy adds to each request, proving the client-certificate header came from it. Required for EST re-enrollment. */
    EST_PROXY_SECRET: optional(z.string().min(32, 'EST_PROXY_SECRET must be at least 32 characters')),
    /** Request header that carries EST_PROXY_SECRET. */
    EST_PROXY_SECRET_HEADER: z.string().trim().min(1).default('x-certifly-proxy-secret'),
    /** Disable rate limits (trusted setups). */
    RATE_LIMITS_DISABLED: flag,
    SETUP_TOKEN: optional(z.string()),
    PKI_BASE_URL: optional(z.url()),
    /** Port certifly connects to when it validates an ACME http-01 challenge. */
    ACME_HTTP01_PORT: z.coerce.number().int().min(1).max(65535).default(80),
    /** Port certifly connects to when it validates an ACME tls-alpn-01 challenge. */
    ACME_TLSALPN01_PORT: z.coerce.number().int().min(1).max(65535).default(443),
    SMTP_URL: optional(z.string()),
    SMTP_FROM: optional(z.string()),
    /** Write mails as files into this directory instead of sending them (tests). */
    MAIL_OUTBOX_DIR: optional(z.string()),
    OIDC_ISSUER: optional(z.url()),
    OIDC_CLIENT_ID: optional(z.string()),
    OIDC_CLIENT_SECRET: optional(z.string()),
    OIDC_DISPLAY_NAME: z.string().default('SSO'),
    OIDC_SCOPES: z.string().default('openid profile email'),
    /** Name of the ID token claim that lists the person's groups at the provider; mapped onto certifly groups at sign-in. */
    OIDC_GROUPS_CLAIM: optional(z.string()),
  })
  .superRefine((env, ctx) => {
    const issue = (path: string, message: string) => ctx.addIssue({ code: 'custom', path: [path], message })
    if (!env.CERTIFLY_MASTER_KEY) return issue('CERTIFLY_MASTER_KEY', 'required (or CERTIFLY_MASTER_KEY_FILE); generate one with: openssl rand -hex 32')
    // The master key protects the CA keys, the secret key only sessions and small secrets. One
    // value for both would let a leaked session secret decrypt every CA key.
    const problem = masterKeyProblem(env.CERTIFLY_MASTER_KEY, env.SECRET_KEY)
    if (problem) issue('CERTIFLY_MASTER_KEY', problem)
    for (const previous of (env.CERTIFLY_MASTER_KEY_PREVIOUS ?? '').split(/[\s,]+/).filter(Boolean)) {
      const old = masterKeyProblem(previous, env.SECRET_KEY)
      if (old) issue('CERTIFLY_MASTER_KEY_PREVIOUS', old)
    }
  })

export type Env = z.infer<typeof schema>

let cached: Env | undefined

/** Validated process environment. Throws a readable error listing every invalid variable. */
export function env(): Env {
  if (cached) return cached
  const { values, problem } = withMasterKeyFile(process.env)
  if (problem) throw new Error(`Invalid environment configuration:\n  CERTIFLY_MASTER_KEY_FILE: ${problem}`)
  const result = schema.safeParse(values)
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n')
    throw new Error(`Invalid environment configuration:\n${issues}`)
  }
  cached = result.data
  return cached
}

export const hasService = (name: ServiceName) => env().SERVICES.has(name)
