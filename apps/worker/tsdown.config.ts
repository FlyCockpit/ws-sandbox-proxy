import { defineConfig } from "tsdown";

export default defineConfig({
  // Object form keeps the emitted file at `dist/index.mjs` while the real entry
  // is the bootstrap wrapper. See src/bootstrap.ts and apps/server's config.
  entry: { index: "./src/bootstrap.ts" },
  format: "esm",
  outDir: "./dist",
  clean: true,
  // Bundle the workspace (@wssp/*) packages into the output. The runtime
  // image (Dockerfile.worker) ships only this app's dist + node_modules — it
  // does NOT copy packages/*/dist — so anything left external would resolve to
  // a dangling node_modules symlink and crash at boot with ERR_MODULE_NOT_FOUND
  // (e.g. "Cannot find package '@wssp/env'"). Mirrors apps/server.
  deps: {
    // Bundle dotenv with `@wssp/env/load-dotenv` so the worker image does not
    // need a resolvable `dotenv` package at runtime. Validation modules never
    // import dotenv. `dotenv` is not a dependency of this app on purpose — it
    // resolves transitively through `@wssp/env`, the only workspace package
    // that declares it. Same rule as apps/server.
    alwaysBundle: [/@wssp\/.*/, "dotenv"],
  },
});
