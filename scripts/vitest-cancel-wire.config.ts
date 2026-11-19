import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Explicit cross-language contract gate. Build the host first with
// cargo build -p wssp --bin wssp --locked; no compiler runs inside the test.
export default defineConfig({
  test: {
    clearMocks: false,
    environment: "node",
    include: ["apps/server/src/sandbox-relay/cancel-wire.contract.test.ts"],
    setupFiles: [fileURLToPath(new URL("./test-io-guard.ts", import.meta.url))],
    maxWorkers: 1,
    // Every case boots a real daemon against the Python Incus double, whose
    // process spawns slow sharply under parallel load. Setup alone may take
    // the test's SESSION_TIMEOUT_MS (60 s, the first session's host
    // observation) plus BOOTSTRAP_TIMEOUT_MS (125 s, the IncusClient
    // readiness bound plus relay delivery), so the case budget covers that
    // plus a body of 12 s steps (CASE_TIMEOUT_MS in the test). Hangs still
    // fail fast on until()'s labelled bounds.
    testTimeout: 240_000,
  },
});
