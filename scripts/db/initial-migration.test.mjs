import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  checkStatements,
  frozenSection,
  INITIAL_PATH,
  initialSql,
} from "./generate-initial-migration.mjs";
import { readMigrationsFolder } from "./lib/migration-state.mjs";
import { MIGRATIONS_DIR, SCHEMA_DIR } from "./lib/prisma.mjs";
import { schemaCheckConstraints } from "./lib/schema-checks.mjs";
import { checkWrapper, splitStatements } from "./lib/sql.mjs";

/**
 * The CHECK statements 0_init's frozen section holds after every later committed
 * migration's `DROP CONSTRAINT` / `ADD CONSTRAINT … CHECK` (in folder order).
 */
function checksAfterLaterMigrations(initial) {
  const statements = new Map(
    initial.split("\n").map((line) => [/ADD CONSTRAINT "([^"]+)"/.exec(line)?.[1], line]),
  );
  for (const { name, sql } of readMigrationsFolder(MIGRATIONS_DIR)) {
    if (name === "0_init") continue;
    for (const { text } of splitStatements(sql)) {
      const dropped = /^ALTER TABLE "[^"]+" DROP CONSTRAINT "([^"]+)";?$/s.exec(text);
      if (dropped) statements.delete(dropped[1]);
      const added = /^ALTER TABLE "[^"]+" ADD CONSTRAINT "([^"]+)" CHECK \(/s.exec(text);
      if (added) statements.set(added[1], `${text.trim().replace(/;?$/, ";")}`);
    }
  }
  return [...statements.values()];
}

test("all 154 documentary CHECKs match 0_init plus later migrations: names, mapped tables and exact expressions", () => {
  const checks = schemaCheckConstraints(SCHEMA_DIR);
  assert.equal(checks.length, 154);
  const sql = readFileSync(INITIAL_PATH, "utf8");
  assert.deepEqual(
    checksAfterLaterMigrations(frozenSection(sql, "checks")).sort(),
    checkStatements(checks).split("\n").sort(),
  );
  const materialized = splitStatements(sql).filter(({ text }) =>
    /^ALTER TABLE .* ADD CONSTRAINT .* CHECK \(/s.test(text),
  );
  assert.equal(materialized.length, checks.length);
  assert.equal(new Set(checks.map(({ constraint }) => constraint)).size, checks.length);
  assert.equal(checkWrapper(sql).ok, true);
});
test("frozen baseline retains ten domain functions, nine triggers and the required transfer host", () => {
  const sql = readFileSync(INITIAL_PATH, "utf8");
  const hardening = frozenSection(sql, "hardening");
  assert.equal((hardening.match(/^CREATE OR REPLACE FUNCTION public\.wssp_/gm) ?? []).length, 10);
  assert.equal((hardening.match(/^CREATE TRIGGER wssp_/gm) ?? []).length, 9);
  assert.match(sql, /"acceptedHostId" TEXT NOT NULL/);
  assert.ok(sql.indexOf("initial-backfill-begin") < sql.indexOf("initial-checks-begin"));
  assert.ok(sql.indexOf("initial-checks-end") < sql.indexOf("initial-hardening-begin"));
});
test("regeneration preserves the frozen backfill and hardening sections without annotation accumulation", () => {
  const sql = readFileSync(INITIAL_PATH, "utf8");
  const hardening = frozenSection(sql, "hardening").replace(
    /^-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline\n/gm,
    "",
  );
  const regenerated = initialSql(
    'CREATE TABLE "fixture" (id TEXT);',
    frozenSection(sql, "backfill"),
    hardening,
    schemaCheckConstraints(SCHEMA_DIR),
  );
  assert.equal(frozenSection(regenerated, "hardening"), frozenSection(sql, "hardening"));
  assert.throws(() => frozenSection("", "hardening"), /Missing or ambiguous/);
});
