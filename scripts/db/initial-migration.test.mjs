import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  checkStatements,
  frozenSection,
  INITIAL_PATH,
  initialSql,
} from "./generate-initial-migration.mjs";
import { SCHEMA_DIR } from "./lib/prisma.mjs";
import { schemaCheckConstraints } from "./lib/schema-checks.mjs";
import { checkWrapper, splitStatements } from "./lib/sql.mjs";

test("all 145 documentary CHECKs match 0_init names, mapped tables and exact expressions", () => {
  const checks = schemaCheckConstraints(SCHEMA_DIR);
  assert.equal(checks.length, 145);
  const sql = readFileSync(INITIAL_PATH, "utf8");
  assert.equal(frozenSection(sql, "checks"), checkStatements(checks));
  const materialized = splitStatements(sql).filter(({ text }) =>
    /^ALTER TABLE .* ADD CONSTRAINT .* CHECK \(/s.test(text),
  );
  assert.equal(materialized.length, checks.length);
  assert.equal(new Set(checks.map(({ constraint }) => constraint)).size, checks.length);
  assert.equal(checkWrapper(sql).ok, true);
});
test("frozen baseline retains eight domain functions, seven triggers and the required transfer host", () => {
  const sql = readFileSync(INITIAL_PATH, "utf8");
  const hardening = frozenSection(sql, "hardening");
  assert.equal((hardening.match(/^CREATE OR REPLACE FUNCTION public\.wssp_/gm) ?? []).length, 8);
  assert.equal((hardening.match(/^CREATE TRIGGER wssp_/gm) ?? []).length, 7);
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
