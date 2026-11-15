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
 * by single `.`/`_`, a double `__`, or runs of `-`. Bounded so every derived
 * container name stays one DNS label (at most 63 bytes).
 */
const PREFIX_ENV = "TEST_CONTAINER_PREFIX";
export const DEFAULT_TEST_CONTAINER_PREFIX = "wssp";
const PREFIX = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const MAX_PREFIX = 24;

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
  if (!prefix || prefix.length > MAX_PREFIX || !PREFIX.test(prefix))
    throw new Error(
      `${source} needs a Docker name prefix: lowercase letters and digits joined by ".", "_", "__" or "-", at most ${MAX_PREFIX} characters`,
    );
  return prefix;
}
