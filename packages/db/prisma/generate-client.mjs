/**
 * `prisma generate`, skipped when the generated client already matches its
 * inputs. Run by this package's `postinstall` and `db:generate`, and through
 * Turbo before every `check-types` and `test:pg` (turbo.json), so neither ever
 * reads a client generated from another branch's schema.
 *
 * The inputs are hashed into SCHEMA_STAMP inside the generated directory: every
 * file under prisma/schema/, prisma.config.ts, and the installed `prisma` and
 * `@prisma/client` versions. A missing or different stamp regenerates. The
 * stamp is removed before generating and written only after success, so an
 * interrupted generate never looks fresh.
 *
 * Lives under prisma/ (not scripts/) because both Dockerfiles run the
 * postinstall with only package.json files and packages/db/prisma* copied.
 *
 *   node prisma/generate-client.mjs           regenerate if stale
 *   node prisma/generate-client.mjs --force   always regenerate
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** Bump to force one regeneration everywhere when the hashed inputs change shape. */
const STAMP_FORMAT = "wssp-prisma-client-stamp/1";
export const SCHEMA_STAMP = ".wssp-schema-hash";
const VERSIONED_PACKAGES = ["prisma", "@prisma/client"];

function filesUnder(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...filesUnder(path));
    else if (entry.isFile()) found.push(path);
  }
  return found;
}

function installedVersion(packageDir, name) {
  const manifest = join(packageDir, "node_modules", name, "package.json");
  return existsSync(manifest) ? JSON.parse(readFileSync(manifest, "utf8")).version : "missing";
}

/** Content hash of everything the generated client is derived from. */
export function schemaInputsHash(packageDir) {
  const hash = createHash("sha256").update(`${STAMP_FORMAT}\n`);
  const add = (label, content) => {
    hash.update(`${label}\0${content.length}\0`);
    hash.update(content);
  };
  const schemaFiles = filesUnder(join(packageDir, "prisma", "schema"))
    .map((path) => relative(packageDir, path).split(sep).join("/"))
    .sort();
  for (const file of schemaFiles) add(file, readFileSync(join(packageDir, file)));
  add("prisma.config.ts", readFileSync(join(packageDir, "prisma.config.ts")));
  for (const name of VERSIONED_PACKAGES) add(name, installedVersion(packageDir, name));
  return hash.digest("hex");
}

function stampPath(packageDir) {
  return join(packageDir, "prisma", "generated", SCHEMA_STAMP);
}

/** Why the generated client cannot be used as is, or `null` when it is fresh. */
export function staleReason(packageDir, expected = schemaInputsHash(packageDir)) {
  const stamp = stampPath(packageDir);
  if (!existsSync(join(packageDir, "prisma", "generated", "client.ts")))
    return "no generated client";
  if (!existsSync(stamp)) return "generated client has no schema stamp";
  if (readFileSync(stamp, "utf8").trim() !== expected)
    return "schema, Prisma config or Prisma version changed since the last generate";
  return null;
}

function runPrismaGenerate(packageDir) {
  const result = spawnSync(join(packageDir, "node_modules", ".bin", "prisma"), ["generate"], {
    cwd: packageDir,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`prisma generate exited with ${result.status}`);
}

/**
 * Regenerates when stale (or always with `force`) and returns what it did.
 * `generate` is injectable so the staleness logic is testable without Prisma.
 */
export function ensureGeneratedClient(
  packageDir,
  { force = false, generate = runPrismaGenerate, log = console.error } = {},
) {
  const expected = schemaInputsHash(packageDir);
  const reason = force ? "forced" : staleReason(packageDir, expected);
  if (reason === null) {
    log("Prisma client is up to date with prisma/schema; not regenerating.");
    return { generated: false, reason: null };
  }
  log(`Regenerating Prisma client: ${reason}.`);
  rmSync(stampPath(packageDir), { force: true });
  generate(packageDir);
  if (!existsSync(join(packageDir, "prisma", "generated")))
    throw new Error("prisma generate did not create prisma/generated");
  writeFileSync(stampPath(packageDir), `${expected}\n`);
  return { generated: true, reason };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    ensureGeneratedClient(fileURLToPath(new URL("..", import.meta.url)), {
      force: process.argv.includes("--force"),
    });
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
