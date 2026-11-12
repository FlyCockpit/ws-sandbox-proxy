import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// Real-PostgreSQL layer: only `*.pg.test.ts`, only via `pnpm test:pg`
// (scripts/test-pg.mjs owns the one disposable container and the template
// database). No TCP I/O guard here: these tests connect to that container.
// Each file clones its own database from the template (see
// packages/db/src/testing/pg.ts), so files are isolated and may run in
// parallel; two workers keep the 7.6 GiB development host comfortable.
export default defineConfig({
  test: {
    clearMocks: false,
    globals: false,
    environment: "node",
    include: ["src/**/*.pg.test.ts"],
    globalSetup: [fileURLToPath(new URL("./scripts/vitest-pg-global-setup.ts", import.meta.url))],
    maxWorkers: 2,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
