import { defineConfig } from "vitest/config";

// Real-S3 layer: only `*.s3.test.ts`, only via `pnpm test:s3`
// (scripts/test-s3.mjs owns the one disposable S3 gateway). No TCP I/O guard:
// these tests talk to that loopback container.
export default defineConfig({
  test: {
    clearMocks: false,
    globals: false,
    environment: "node",
    include: ["src/**/*.s3.test.ts"],
    maxWorkers: 1,
    testTimeout: 60_000,
  },
});
