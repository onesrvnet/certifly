import { fileURLToPath } from 'node:url'

const rootDir = fileURLToPath(new URL('..', import.meta.url))
/** `TEST_BUILD_DIR` lets two test runs in one checkout build side by side; `.nuxt-test` by default. */
const buildDirName = process.env.TEST_BUILD_DIR || '.nuxt-test'
const buildDir = fileURLToPath(new URL(`../${buildDirName}`, import.meta.url))

/**
 * Options for `setup()` in API tests. The app is built once per run by the global
 * setup (`buildServer`), so each test file only starts a server. Builds into its own
 * directory so a running dev server (which owns `.nuxt`) is not disturbed.
 */
export const serverOptions = {
  rootDir,
  buildDir,
  build: false,
  nuxtConfig: { buildDir: buildDirName },
}

/**
 * Build the app for the API tests, with the overrides `@nuxt/test-utils` would apply
 * when building per file. Set TEST_SKIP_BUILD=1 to reuse the previous build.
 *
 * Built without database settings, like the image: NuxtHub would otherwise write the
 * DATABASE_URL of the moment into the bundle, which a reused build would then keep after its
 * throwaway database is gone.
 */
export async function buildServer() {
  if (process.env.TEST_SKIP_BUILD === '1') return
  const saved = { DATABASE_URL: process.env.DATABASE_URL, POSTGRES_URL: process.env.POSTGRES_URL, POSTGRESQL_URL: process.env.POSTGRESQL_URL }
  for (const key of Object.keys(saved)) delete process.env[key]
  const { buildNuxt, loadNuxt } = await import('nuxt/kit')
  const nuxt = await loadNuxt({
    cwd: rootDir,
    dev: false,
    dotenv: false,
    overrides: {
      ...serverOptions.nuxtConfig,
      nitro: { output: { dir: `${buildDir}/output` } },
      compatibilityDate: '2024-04-03',
      // Browser tests report what differs when server and browser render a page differently.
      vite: { define: { __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'true' } },
    },
  })
  try {
    await buildNuxt(nuxt)
  } finally {
    await nuxt.close()
    for (const [key, value] of Object.entries(saved)) if (value !== undefined) process.env[key] = value
  }
}
