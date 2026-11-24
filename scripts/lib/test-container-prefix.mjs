/**
 * The Docker name prefix of every disposable test fixture (test:pg,
 * test:s3, backup:test, db:test-migrations, runtime:test-operations).
 *
 * `--container-prefix <name>` (where a harness takes flags) wins; otherwise
 * TEST_CONTAINER_PREFIX; otherwise the harness's default (`wssp`). The
 * variable lets a chained run (`pnpm verify`, CI) keep a shared machine's
 * containers, networks and images in their own namespace without passing
 * arguments through.
 *
 * A valid prefix is a Docker container/network/volume name AND, with a
 * suffix, an image repository path component: lowercase alphanumerics joined
 * by single `.`/`_`, a double `__`, or runs of `-`. Bounded so a name built
 * from it stays short: the disposable PostgreSQL name, which is also the
 * server's 63-byte `cluster_name`, fits for every accepted prefix
 * (scripts/lib/disposable-postgres.mjs).
 */
const PREFIX_ENV = "TEST_CONTAINER_PREFIX";
export const DEFAULT_TEST_CONTAINER_PREFIX = "wssp";
const PREFIX = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
export const MAX_TEST_CONTAINER_PREFIX = 24;

/**
 * @param {{ argv?: string[], env?: NodeJS.ProcessEnv, fallback?: string }} [options]
 *   argv: the harness's own arguments, when it accepts `--container-prefix`.
 */
export function testContainerPrefix({
  argv = [],
  env = process.env,
  fallback = DEFAULT_TEST_CONTAINER_PREFIX,
} = {}) {
  const index = argv.indexOf("--container-prefix");
  if (index === -1 && env[PREFIX_ENV] === undefined) return fallback;
  const [prefix, source] =
    index === -1 ? [env[PREFIX_ENV], PREFIX_ENV] : [argv[index + 1], "--container-prefix"];
  if (!prefix || prefix.length > MAX_TEST_CONTAINER_PREFIX || !PREFIX.test(prefix))
    throw new Error(
      `${source} needs a Docker name prefix: lowercase letters and digits joined by ".", "_", "__" or "-", at most ${MAX_TEST_CONTAINER_PREFIX} characters`,
    );
  return prefix;
}
