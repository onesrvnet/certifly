import { existsSync } from 'node:fs'
import { defineConfig } from 'vitest/config'

// The api and e2e projects run against the built app; they only exist once it has its test setup.
const webTests = existsSync(new URL('./test/global-setup.ts', import.meta.url))

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['packages/*/test/**/*.test.ts', 'test/unit/**/*.test.ts'],
        },
      },
      ...(webTests
        ? [
            {
              test: {
                name: 'api',
                root: '.',
                include: ['test/api/**/*.test.ts'],
                globalSetup: ['./test/global-setup.ts'],
                testTimeout: 30_000,
                hookTimeout: 180_000,
                fileParallelism: false,
              },
            },
            {
              test: {
                name: 'e2e',
                root: '.',
                include: ['test/e2e/**/*.test.ts'],
                globalSetup: ['./test/global-setup.ts'],
                testTimeout: 60_000,
                hookTimeout: 180_000,
                fileParallelism: false,
              },
            },
          ]
        : []),
    ],
  },
})
