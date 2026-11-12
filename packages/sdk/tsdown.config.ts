import { defineConfig } from "tsdown";

export default defineConfig({
  entry: { index: "./src/index.ts", webhooks: "./src/webhooks/index.ts" },
  format: "esm",
  platform: "node",
  outDir: "./dist",
  clean: true,
  // The declaration generator emits relative to its tsconfig's directory, so
  // the config that also compiles the inlined contracts source lives at the
  // common ancestor (the repo root).
  dts: { tsconfig: "../../tsconfig.sdk-dts.json" },
  deps: {
    // @wssp/sandbox-contracts is a private workspace package: inline it (code
    // and declarations) so the published tarball depends on zod alone.
    alwaysBundle: [/^@wssp\//],
  },
});
