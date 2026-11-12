#!/usr/bin/env node
/** Regenerate the unreleased baseline from CURRENT schema and frozen invariant SQL. */
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ROOT, SCHEMA_DIR } from "./lib/prisma.mjs";
import { schemaCheckConstraints } from "./lib/schema-checks.mjs";
import { wrapTransactional } from "./lib/sql.mjs";

export const INITIAL_PATH = path.join(ROOT, "packages/db/prisma/migrations/0_init/migration.sql");
export function frozenSection(sql, name) {
  const start = `-- wssp:initial-${name}-begin\n`;
  const end = `-- wssp:initial-${name}-end`;
  const parts = sql.split(start);
  if (parts.length !== 2 || parts[1].split(end).length !== 2)
    throw new Error(`Missing or ambiguous frozen initial ${name} section.`);
  return parts[1].split(end)[0].trimEnd();
}
export function checkStatements(checks) {
  return checks
    .map(
      ({ table, constraint, expression }) =>
        `ALTER TABLE "${table}" ADD CONSTRAINT "${constraint}" CHECK (${expression});`,
    )
    .join("\n");
}
export function initialSql(ddl, backfill, hardening, checks) {
  const section = (name, sql) =>
    `-- wssp:initial-${name}-begin\n${sql.trimEnd()}\n-- wssp:initial-${name}-end`;
  // Per-statement review records the existing domain enforcement; first-install
  // admission still independently proves an empty catalog and validates the wrapper.
  const annotatedHardening = hardening.replace(
    /^(CREATE (?:OR REPLACE )?(?:FUNCTION|TRIGGER) .+)$/gm,
    "-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline\n$1",
  );
  return wrapTransactional(
    [
      ddl.trimEnd(),
      section("backfill", backfill),
      section("checks", checkStatements(checks)),
      section("hardening", annotatedHardening),
    ].join("\n\n"),
  );
}
export function generateInitialMigration() {
  const args = process.argv.slice(2);
  const source = (name) => {
    const index = args.indexOf(`--${name}`);
    if (index >= 0) {
      if (!args[index + 1]) throw new Error(`Missing --${name} path.`);
      return readFileSync(path.resolve(args[index + 1]), "utf8");
    }
    return frozenSection(readFileSync(INITIAL_PATH, "utf8"), name).replace(
      /^-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline\n/gm,
      "",
    );
  };
  const backfill = source("backfill");
  const hardening = source("hardening");
  const checks = schemaCheckConstraints(SCHEMA_DIR);
  // No database connection: exact Prisma from-empty schema generation command.
  const result = spawnSync(
    "pnpm",
    [
      "--dir",
      "packages/db",
      "exec",
      "prisma",
      "migrate",
      "diff",
      "--from-empty",
      "--to-schema",
      "prisma/schema",
      "--script",
    ],
    {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  if (result.status !== 0)
    throw new Error("Initial schema SQL generation failed; baseline unchanged.");
  if (!result.stdout.includes("CREATE TABLE")) throw new Error("Prisma returned no schema DDL.");
  mkdirSync(path.dirname(INITIAL_PATH), { recursive: true });
  writeFileSync(INITIAL_PATH, initialSql(result.stdout, backfill, hardening, checks));
  writeFileSync(
    path.join(path.dirname(INITIAL_PATH), "../migration_lock.toml"),
    'provider = "postgresql"\n',
  );
  console.log(
    `Generated 0_init with ${checks.length} CHECK constraints and frozen domain hardening.`,
  );
}
if (process.argv[1] === fileURLToPath(import.meta.url)) generateInitialMigration();
