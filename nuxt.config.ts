import { fileURLToPath } from 'node:url'
import tailwindcss from '@tailwindcss/vite'

// The tables live in packages/db because the framework-free core imports them; NuxtHub
// only needs to know where they are to generate migrations and to type `db`.
const schemaEntry = fileURLToPath(new URL('./packages/db/src/schema/index.ts', import.meta.url))
// The Reflect metadata shim that @peculiar/x509's tsyringe needs, and the module that imports it
// ahead of x509; see `nitro` below.
const reflectShim = ['reflect.ts', 'x509.ts'].map((file) => fileURLToPath(new URL(`./packages/pki/src/${file}`, import.meta.url)))

export default defineNuxtConfig({
  compatibilityDate: '2026-10-01',
  devtools: { enabled: true },
  modules: ['@nuxthub/core', 'shadcn-nuxt', '@pinia/nuxt', '@nuxtjs/i18n'],
  css: [
    '@fontsource-variable/ibm-plex-sans/wght.css',
    '@fontsource-variable/ibm-plex-sans/wght-italic.css',
    '@fontsource/ibm-plex-mono/400.css',
    '@fontsource/ibm-plex-mono/500.css',
    '~/assets/css/main.css',
  ],
  app: {
    head: {
      link: [
        { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
        { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' },
      ],
      meta: [
        { name: 'theme-color', content: '#ffffff', media: '(prefers-color-scheme: light)' },
        { name: 'theme-color', content: '#0a0a0a', media: '(prefers-color-scheme: dark)' },
      ],
    },
  },
  vite: {
    plugins: [tailwindcss()],
  },
  shadcn: {
    prefix: '',
    componentDir: './app/components/ui',
  },
  hub: {
    db: {
      dialect: 'postgresql',
      driver: 'postgres-js',
      casing: 'snake_case',
      // The image is built without database credentials; the server applies migrations itself
      // when it starts (server/plugins/00.migrate.ts).
      applyMigrationsDuringBuild: false,
      // Off because server/plugins/00.migrate.ts applies them in dev as well, with the same
      // runner under an advisory lock; NuxtHub's own dev plugin would race with it.
      applyMigrationsDuringDev: false,
    },
  },
  // @peculiar/x509 loads tsyringe, which throws at load time unless Reflect.getMetadata exists.
  // packages/pki imports a small shim for it before x509, and both settings keep that order in
  // the server bundle: an external package would be imported by the bundle's entry before any
  // inlined code runs, so x509 and tsyringe are bundled too and then run in import order; and
  // Nitro's tree-shaking drops side-effect-only imports unless both the shim and the module
  // importing it are listed as having side effects.
  nitro: {
    externals: { inline: ['@peculiar/x509', 'tsyringe'] },
    moduleSideEffects: reflectShim,
  },
  hooks: {
    'hub:db:schema:extend': ({ paths }: { paths: string[] }) => {
      paths.push(schemaEntry)
    },
  },
  i18n: {
    defaultLocale: 'en',
    strategy: 'no_prefix',
    locales: [{ code: 'en', language: 'en-US', name: 'English', file: 'en.json' }],
    detectBrowserLanguage: { useCookie: true, cookieKey: 'certifly_locale', redirectOn: 'root' },
  },
  typescript: {
    strict: true,
  },
})
