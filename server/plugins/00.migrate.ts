export default defineNitroPlugin(() => {
  // A bad configuration (for example a master key equal to the secret key) stops the start here.
  env()
  keyProviderReady().catch((error) => {
    console.error('[keys] the master key could not be loaded', error)
    process.exit(1)
  })
  // Nitro does not wait for async plugins, so requests wait in 00.migrations.ts instead.
  migrationsReady().catch((error) => {
    // Without a current schema nothing works; exit so the orchestrator restarts us.
    console.error('[migrate] failed to apply migrations', error)
    process.exit(1)
  })
})
