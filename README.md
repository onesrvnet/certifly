<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/certifly-icon-light.svg">
    <img src="brand/certifly-icon-dark.svg" alt="certifly" width="96" height="96">
  </picture>
</p>

<h1 align="center">certifly</h1>

<p align="center">
  Your own private certificate authority, without the spreadsheet of expiry dates.
</p>

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#what-it-does">What it does</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#license">License</a>
</p>

---

Most teams that run internal TLS end up with the same setup: a root key on someone's laptop or in
a safe, a few `openssl` one-liners in a wiki, and an unpleasant surprise every time a certificate
quietly expires. mTLS makes it worse, because now every client needs a certificate as well.

**certifly** is a small, self-hosted web app for running that private CA properly. Start a fresh
hierarchy with a root created in certifly, or keep the root you already have offline and let
certifly run the intermediates below it. Either way, it hands out webserver, mTLS server and mTLS
client certificates. You can issue them from the UI or the API, and certbot, Caddy, Traefik or
cert-manager will be able to request them on their own once ACME is in. It keeps track of what it
issued and tells you before anything expires.

It is deliberately small. There is one instance and one team, with no organisations, projects or
billing. You can read the whole thing in an afternoon.

## Why we built it

Making a certificate is the easy part. The hard part is everything after: knowing which
certificates exist, who has them, where they're deployed and when each one runs out. It means
renewing them before that happens and revoking the one on the laptop that just went missing,
then making sure every server actually notices. Six months later someone asks "who issued this,
and is it still valid?", and the answer is usually buried in somebody's shell history.

That bookkeeping is what a tool is good at. certifly records every certificate it issues, warns
you before it expires, revokes it in one click, publishes the CRL that servers check, and writes
down who did what. It also enforces the fiddly rules (name constraints, path lengths, key usages)
every time, so nobody has to remember them.

There are tools for this, but the good ones keep moving toward the enterprise. Infisical is a
good example: it has a capable certificate manager, but the parts a small team actually needs
sit behind enterprise licenses and paid plans. That includes ACME, EST, OCSP and importing an
intermediate signed by your own root. Other options are either full-blown platforms that take a
team to operate, or a CLI with no overview of what was issued.

certifly is the tool we wanted for ourselves: the essential PKI workflow in one small app you can
run yourself, with nothing held back behind a paywall.

## Status

**Pre-release.** Everything below is built and tested: the CA hierarchy, templates, issuance,
revocation, ACME, EST, trust bundles, alerts and the SSH CA with its command-line tool. It has
not had an outside security review yet, so treat it as such before it protects anything you
care about.

## What it does

```
   root CA            ◀── created in certifly, or your existing offline root
          │
          ▼
   L2 intermediate    ◀── signed in certifly, or via CSR by the external root
          │
          ▼
   L3 issuing CAs     ◀── signed inside certifly by the L2
          │
          ├── webserver TLS certificates
          ├── mTLS server certificates
          └── mTLS client certificates
```

The depth is up to you: a root with one issuing CA works just as well.

- **Your CA hierarchy, your way.** Create a root in certifly, or bring your own: certifly makes the
  key and CSR, you sign it wherever your root lives and upload the result. Below that, CAs sign
  each other inside certifly. Intermediates require name constraints, so a CA can only ever issue
  for the names you allowed it.
- **Templates.** Rules for what a certificate may contain: which domains and IP ranges, key types,
  maximum lifetime and key usages. Every certificate, however it was requested, goes through one.
- **Issuance.** Paste a CSR, or let certifly generate the key and download it once as PEM or
  PKCS#12. certifly never stores leaf keys.
- **Revocation.** Revoke with a reason. certifly publishes CRLs and the CA certificates at stable
  URLs that are embedded in every certificate it issues.
- **Automation.** ACME (with external account binding) for webservers and EST for devices and
  mTLS clients, plus a plain REST API with API keys.
- **Inventory and alerts.** Import certificates issued elsewhere to track their expiry too. Get
  an email or a webhook before anything runs out.
- **Trust bundles.** Named sets of CA certificates that clients can download to build their
  trust stores.
- **Audit log.** Who issued, revoked or changed what, and when.
- **SSH certificates.** An SSH CA that signs short-lived user certificates and host
  certificates. People sign in with the `certifly` command-line tool (passkey, YubiKey or single
  sign-on in the browser) and get certificates for the host groups their groups may reach; hosts
  join with a one-time token and keep their certificate, the CA key and the revocation list up to
  date on their own.

### The command-line tool

```sh
brew install onesrvnet/tap/certifly   # or see "Installing the CLI" below
certifly login --server certifly.example.com
certifly                              # pick a host and connect
```

On a server, as root: `certifly host join --server certifly.example.com <join token>`. It
configures sshd (checked with `sshd -t` before it is reloaded) and installs a timer that renews
the host certificate and fetches the revocation list every 15 minutes.

Host groups that require a YubiKey need an OpenSSH with FIDO support on the person's machine.
Apple's built-in `ssh` has none; `brew install openssh` provides it.

### On keys

CA private keys are encrypted at rest with a master key that lives outside the database. A stolen
database dump is useless on its own, and so is a database backup without that key. Back up
`CERTIFLY_MASTER_KEY` somewhere safe and offline. There is deliberately no button that exports a
CA key, not even for admins.

## Getting started

You need [Bun](https://bun.sh), Node 24 and Docker.

```sh
git clone https://github.com/onesrvnet/certifly.git
cd certifly
cp .env.sample .env                              # set SECRET_KEY: openssl rand -hex 32
docker compose -f docker/compose.dev.yml up -d   # Postgres, plus Mailpit for email
bun install
bun run dev
```

Open http://localhost:3000 and sign in with your email address. In development, the sign-in code
lands in Mailpit at http://localhost:8025. **The first person to sign in becomes the admin.**
Everyone after that needs an invite, or comes in through your OIDC provider.

### Running it for real

You need Docker with Compose and a domain name pointing at the server. Releases are published
as `ghcr.io/onesrvnet/certifly` for amd64 and arm64.

```sh
mkdir certifly && cd certifly
base=https://raw.githubusercontent.com/onesrvnet/certifly/main
curl -fsSLO $base/compose.yml
curl -fsSLO $base/compose.caddy.yml
mkdir docker && curl -fsSL -o docker/Caddyfile $base/docker/Caddyfile
curl -fsSL -o .env $base/.env.sample
```

Fill in `.env`, generating each secret fresh:

| Variable | Value |
|---|---|
| `URL` | `https://certifly.example.com` |
| `SECRET_KEY` | `openssl rand -hex 32` |
| `CERTIFLY_MASTER_KEY` | `openssl rand -hex 32`, different from `SECRET_KEY`. **Keep a copy offline.** Without it, a backup of the database is useless. |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` |
| `SETUP_TOKEN` | `openssl rand -hex 16`. Only the person holding it can become the first admin. |

Add `SMTP_URL` and `SMTP_FROM` so certifly can send sign-in codes and alerts.

**With Caddy**, which gets a Let's Encrypt certificate by itself (ports 80 and 443 must be
reachable from the internet): set `CERTIFLY_DOMAIN=certifly.example.com`, then

```sh
docker compose -f compose.yml -f compose.caddy.yml up -d
```

**With your own proxy** (Traefik, nginx, …): run `docker compose up -d`. certifly listens on
`127.0.0.1:3000`; terminate TLS in your proxy and set `TRUST_PROXY=true`. certifly then takes
the client address from the last `X-Forwarded-For` entry, the one your proxy adds, so it must be
the only proxy in front of certifly.

Then open `https://certifly.example.com/setup?token=<SETUP_TOKEN>`, create your account and
remove `SETUP_TOKEN` from `.env`. Database migrations run whenever the container starts, so
updating is `docker compose pull && docker compose up -d`.

### Installing the CLI

macOS: `brew install onesrvnet/tap/certifly`, updated with `brew upgrade certifly`.

Linux (and macOS without Homebrew):

```sh
curl -fsSL https://raw.githubusercontent.com/onesrvnet/certifly/main/cli/install.sh | sh
```

It installs the latest release to `/usr/local/bin` (with sudo if needed) after checking its
SHA-256 checksum. Set `INSTALL_DIR` for another folder or `CERTIFLY_VERSION` for a specific
release. `certifly update` installs newer releases later; the TUI shows when one is out.

## Configuration

Everything is configured through environment variables. [.env.sample](.env.sample) explains each
one. The important ones are:

| Variable | What it is for |
|---|---|
| `URL` | Public address of the instance |
| `SECRET_KEY` | Signs sessions and encrypts small secrets. `openssl rand -hex 32` |
| `CERTIFLY_MASTER_KEY` | Encrypts CA private keys. Must differ from `SECRET_KEY`. **Back it up offline.** |
| `DATABASE_URL` | PostgreSQL connection string |
| `SETUP_TOKEN` | One-time token the first sign-in must present |
| `SMTP_URL`, `SMTP_FROM` | Outgoing email for sign-in codes, invites and alerts |
| `OIDC_*` | Optional single sign-on through your identity provider |
| `PKI_BASE_URL` | Base for the CRL and CA certificate URLs written into certificates. Defaults to `URL` |
| `SERVICES` | Which roles this process runs: `web`, `worker`, `cron` |
| `OIDC_GROUPS_CLAIM` | ID token claim whose values map onto certifly groups at sign-in |
| `EST_PROXY_SECRET` | Shared secret the TLS proxy sends, so EST re-enrollment can trust its client-certificate header |
| `ACME_HTTP01_PORT`, `ACME_TLSALPN01_PORT` | Ports for ACME challenge checks (80 and 443) |

## Development

| Command | What it does |
|---|---|
| `bun run dev` | Start the app with hot reload |
| `bun run typecheck` | Type-check every workspace |
| `bun run test:unit` | Unit tests; no services needed |
| `bun run test:api` | API tests against the dev stack |
| `bun run db:generate` | Generate a migration after changing the schema |
| `cd cli && go test ./...` | Tests of the command-line tool |

certifly is a [Nuxt](https://nuxt.com) app at the repository root, on top of framework-free Bun workspace
packages in `packages/`. Domain logic and permissions live in `packages/core` and the database
schema in `packages/db`.

## License

certifly is **source-available** under the [Business Source License 1.1](LICENSE). You may read,
change and run it, including in production for your own company. You may not offer it to others
as a hosted or managed service. Each version becomes Apache-2.0 four years after its release.

Need different terms? Get in touch with [onesrv](https://onesrv.net).
