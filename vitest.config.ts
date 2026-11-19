import { fileURLToPath } from "node:url";

import { configDefaults, defineConfig } from "vitest/config";

const testIoGuard = fileURLToPath(new URL("./scripts/test-io-guard.ts", import.meta.url));
const webSrc = fileURLToPath(new URL("./apps/web/src", import.meta.url));
const tanstackStartStub = fileURLToPath(
  new URL("./packages/api/src/test/tanstack-react-start-stub.ts", import.meta.url),
);
const tanstackStartServerStub = fileURLToPath(
  new URL("./packages/api/src/test/tanstack-react-start-server-stub.ts", import.meta.url),
);
const tanstackRouterStub = fileURLToPath(
  new URL("./packages/api/src/test/tanstack-react-router-stub.ts", import.meta.url),
);

export default defineConfig({
  resolve: {
    alias: [
      { find: "@", replacement: webSrc },
      { find: "@tanstack/react-start/server", replacement: tanstackStartServerStub },
      { find: "@tanstack/react-start", replacement: tanstackStartStub },
      { find: "@tanstack/react-router", replacement: tanstackRouterStub },
    ],
  },
  test: {
    clearMocks: false,
    globals: false,
    environment: "node",
    passWithNoTests: true,
    // Hermetic unit tests are CPU-bound, so their wall time scales with
    // machine load. Vitest's generic 5 s default left ~25% headroom: whole
    // component flows took 3.8 s with one other heavy job on the 8-core
    // development host and 5.1-5.5 s at load average ~20. 15 s keeps a hang a
    // fast failure; tests with a longer intrinsic budget still set their own.
    testTimeout: 15_000,
    setupFiles: [testIoGuard],
    // `*.pg.test.ts` needs a real PostgreSQL and runs only under `pnpm test:pg`.
    exclude: [
      ...configDefaults.exclude,
      "**/dist/**",
      "**/dev-dist/**",
      "**/*.contract.test.ts",
      "**/*.pg.test.ts",
      // `*.s3.test.ts` needs the disposable S3 gateway (`pnpm test:s3`).
      "**/*.s3.test.ts",
    ],
  },
});
