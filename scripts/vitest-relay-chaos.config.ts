import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// WP1 reconnect chaos gate. `pnpm test:relay-chaos` runs the PR subset of
// `apps/server/src/sandbox-relay/relay-chaos-matrix.ts`; `--mode full`
// (`pnpm test:relay-chaos:full`) runs every cell. The cells drive the real
// debug daemon: build it first (`cargo build -p wssp --bin wssp --locked`,
// which the package script does). A `pending` cell is skipped.
// The loopback guard admits in-process loopback servers only: the proxy dials
// its upstream, which the unit guard forbids.
export default defineConfig(({ mode }) => ({
  test: {
    clearMocks: false,
    environment: "node",
    include: [
      "apps/server/src/sandbox-relay/relay-fault-proxy-harness.contract.test.ts",
      "apps/server/src/sandbox-relay/relay-chaos.contract.test.ts",
    ],
    setupFiles: [fileURLToPath(new URL("./test-io-guard-loopback.ts", import.meta.url))],
    env: { RELAY_CHAOS_SUBSET: mode === "full" ? "full" : "pr" },
    maxWorkers: 1,
    testTimeout: 20000,
  },
}));
