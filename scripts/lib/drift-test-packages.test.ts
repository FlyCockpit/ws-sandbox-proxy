import assert from "node:assert/strict";
import { test } from "node:test";
import { driftTestPackages } from "./drift-test-packages.ts";

const ALL = [
  "@wssp/api",
  "@wssp/auth",
  "@wssp/locales",
  "@wssp/login-definition",
  "@wssp/sandbox-contracts",
  "@wssp/sdk",
  "server",
  "web",
];

test("a Rust-only change selects the packages that read crates/", () => {
  assert.deepEqual(driftTestPackages(["crates/sandbox-runtime/src/incus/dns_stub_peer.rs"]), [
    "@wssp/api",
    "@wssp/sandbox-contracts",
    "@wssp/sdk",
    "server",
  ]);
});

test("each out-of-package tree selects its readers", () => {
  assert.deepEqual(driftTestPackages(["apps/cli/src/commands/connect.rs"]), [
    "@wssp/locales",
    "@wssp/sdk",
    "server",
  ]);
  assert.deepEqual(driftTestPackages(["docs/guide/pools.md"]), [
    "@wssp/api",
    "@wssp/locales",
    "@wssp/login-definition",
    "@wssp/sdk",
    "web",
  ]);
  assert.deepEqual(driftTestPackages(["scripts/lib/env-manifest.ts"]), [
    "@wssp/api",
    "@wssp/auth",
    "@wssp/sdk",
  ]);
  assert.deepEqual(driftTestPackages([".github/workflows/cli-ci.yml"]), [
    "@wssp/sandbox-contracts",
  ]);
  assert.deepEqual(driftTestPackages([".env.docker.defaults"]), ["web"]);
});

test("workspace-only changes add nothing; --affected already covers them", () => {
  assert.deepEqual(
    driftTestPackages([
      "packages/api/src/index.ts",
      "apps/web/src/main.tsx",
      "apps/client/x.ts",
      "documentation/x.md",
    ]),
    [],
  );
  assert.deepEqual(driftTestPackages([]), []);
});

test("a mixed diff is the union, deduplicated", () => {
  assert.deepEqual(
    driftTestPackages(["crates/a.rs", "apps/cli/b.rs", "docs/c.md", "scripts/d.ts", ".github/e"]),
    ALL,
  );
});

test("an unknown diff runs every drift-test package", () => {
  assert.deepEqual(driftTestPackages(null), ALL);
});
