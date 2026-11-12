/**
 * Drift tests: workspace tests that read files outside every workspace package
 * (Rust sources and protocol fixtures, docs, scripts, CI workflows). Turbo
 * maps such a change to the root package only, so `turbo run test --affected`
 * never selects the package that reads it. `scripts/verify-fast-tests.ts` adds
 * these packages explicitly; each one's `turbo.json` lists the same files as
 * test inputs so the cache does not replay a stale pass.
 *
 * Keep this table in step with those `$TURBO_ROOT$/...` test inputs.
 */
const DRIFT_TEST_PACKAGES: ReadonlyArray<{ prefix: string; packages: readonly string[] }> = [
  { prefix: "crates/", packages: ["server", "@wssp/api", "@wssp/sandbox-contracts", "@wssp/sdk"] },
  { prefix: "apps/cli/", packages: ["server", "@wssp/sdk", "@wssp/locales"] },
  {
    prefix: "docs/",
    packages: ["@wssp/api", "@wssp/sdk", "@wssp/locales", "@wssp/login-definition", "web"],
  },
  { prefix: "scripts/", packages: ["@wssp/api", "@wssp/auth", "@wssp/sdk"] },
  { prefix: ".github/", packages: ["@wssp/sandbox-contracts"] },
  { prefix: ".env.docker.defaults", packages: ["web"] },
];

const ALL = [...new Set(DRIFT_TEST_PACKAGES.flatMap((entry) => entry.packages))].sort();

/**
 * The drift-test packages a change touches. `null` means the changed paths
 * could not be determined; every drift-test package then runs.
 */
export function driftTestPackages(changedPaths: readonly string[] | null): string[] {
  if (changedPaths === null) return ALL;
  const selected = new Set<string>();
  for (const path of changedPaths) {
    for (const entry of DRIFT_TEST_PACKAGES) {
      if (path.startsWith(entry.prefix)) for (const name of entry.packages) selected.add(name);
    }
  }
  return [...selected].sort();
}
