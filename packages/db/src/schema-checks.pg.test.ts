/** Committed migration CHECKs and triggers, exercised on an isolated real PostgreSQL clone. */
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { pgTestDatabase } from "./testing/pg";

type PgError = Error & { code?: string; constraint?: string; table?: string };
type PgClient = {
  connect(): Promise<void>;
  query<Row = Record<string, unknown>>(text: string, values?: unknown[]): Promise<{ rows: Row[] }>;
  end(): Promise<void>;
};

type Check = { table: string; name: string; constraint: string; expression: string };
const { schemaCheckConstraints } = (await import(
  new URL("../../../scripts/db/lib/schema-checks.mjs", import.meta.url).href
)) as { schemaCheckConstraints(directory: string): Check[] };
const repoChecks = schemaCheckConstraints(
  fileURLToPath(new URL("../prisma/schema", import.meta.url)),
);

const db = await pgTestDatabase();
const { Client } = createRequire(import.meta.url)("pg") as {
  Client: new (options: { connectionString: string }) => PgClient;
};
const client = new Client({ connectionString: db.url });
beforeAll(() => client.connect());
afterAll(async () => {
  await client.end();
  await db.close();
});

/** Runs `work` in a transaction that is always rolled back. */
async function inRolledBackTransaction<T>(work: () => Promise<T>): Promise<T> {
  await client.query("BEGIN");
  try {
    return await work();
  } finally {
    await client.query("ROLLBACK");
  }
}

async function failure(sql: string): Promise<PgError> {
  const error = await client.query(sql).then(
    () => undefined,
    (caught: unknown) => caught as PgError,
  );
  expect(error).toBeDefined();
  return error!;
}

describe("committed CHECK declarations (real PostgreSQL)", () => {
  it("freezes every model declaration's mapped table, deterministic name and exact expression", async () => {
    // 0_init, then every later committed migration (a later folder may replace a CHECK).
    const migrations = new URL("../prisma/migrations/", import.meta.url);
    const sql = readdirSync(migrations, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort()
      .map((name) => readFileSync(new URL(`${name}/migration.sql`, migrations), "utf8"))
      .join("\n");
    expect(repoChecks).toHaveLength(156);
    const live = (
      await client.query<{ table: string; name: string; valid: boolean }>(
        `SELECT t.relname AS "table", c.conname AS name, c.convalidated AS valid
       FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
       JOIN pg_namespace n ON n.oid = t.relnamespace
       WHERE c.contype = 'c' AND n.nspname = 'public'
         AND t.relname NOT IN ('_wssp_migration', '_wssp_instance', '_wssp_hold', '_wssp_cluster', '_prisma_migrations')`,
      )
    ).rows;
    for (const check of repoChecks) {
      expect(sql).toContain(
        `ALTER TABLE "${check.table}" ADD CONSTRAINT "${check.constraint}" CHECK (${check.expression});`,
      );
      expect(
        live.find((row) => row.table === check.table && row.name === check.constraint),
      ).toMatchObject({ valid: true });
    }
    expect(live).toHaveLength(repoChecks.length);
  });

  it("rejects a violating row with the committed constraint and table in SQLSTATE 23514", async () => {
    await inRolledBackTransaction(async () => {
      const userId = `user-${randomUUID()}`;
      await client.query(`INSERT INTO "user" (id, name, email) VALUES ($1, 'Owner', $2)`, [
        userId,
        `${userId}@example.test`,
      ]);
      const templateId = `tmpl-${randomUUID()}`;
      await client.query(
        `INSERT INTO sandbox_logical_template (id, "userId", slug, label, "updatedAt") VALUES ($1, $2, 'probe', 'label', CURRENT_TIMESTAMP)`,
        [templateId, userId],
      );
      const check = repoChecks.find((item) => item.name === "sandbox_revision_number")!;
      const error = await client
        .query(
          `INSERT INTO sandbox_template_revision (id, "userId", "templateId", revision, "incusFingerprint", architecture, "manifestDigest") VALUES ($1, $2, $3, 0, $4, 'x86_64', $5)`,
          [`rev-${randomUUID()}`, userId, templateId, `sha256:${"d".repeat(64)}`, "d".repeat(64)],
        )
        .then(
          () => undefined,
          (caught: unknown) => caught as PgError,
        );
      expect(error).toMatchObject({
        code: "23514",
        constraint: check.constraint,
        table: check.table,
      });
    });
  });
});

describe("VM size storage (real PostgreSQL)", () => {
  it("has non-null allocation defaults on all durable rows and nullable report columns", async () => {
    const columns = await client.query<{
      table_name: string;
      column_name: string;
      is_nullable: string;
      column_default: string | null;
    }>(
      `SELECT table_name, column_name, is_nullable, column_default FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name IN ('sandbox_template_revision', 'sandbox_instance', 'sandbox_placement')
       AND column_name IN ('cpuCount', 'memoryMiB') ORDER BY table_name, column_name`,
    );
    expect(columns.rows).toHaveLength(6);
    for (const column of columns.rows) {
      expect(column.is_nullable).toBe("NO");
      expect(column.column_default).toBe(column.column_name === "cpuCount" ? "1" : "1024");
    }
  });

  it("enforces allocation and report bounds while allowing reserved memory above budget", async () => {
    await inRolledBackTransaction(async () => {
      const owner = randomUUID();
      await client.query(`INSERT INTO "user" (id, name, email) VALUES ($1, 'Owner', $2)`, [
        owner,
        `${owner}@example.test`,
      ]);
      const host = randomUUID();
      await client.query(
        `INSERT INTO sandbox_host (id, "userId", slug, label) VALUES ($1, $2, 'b1', 'B1')`,
        [host, owner],
      );
      expect(
        (
          await client.query(
            `SELECT "memoryReservedMiB", "daemonMemoryBudgetMiB", "daemonMaxCpuCount" FROM sandbox_host WHERE id=$1`,
            [host],
          )
        ).rows,
      ).toEqual([{ memoryReservedMiB: 0, daemonMemoryBudgetMiB: null, daemonMaxCpuCount: null }]);
      await client.query(
        `UPDATE sandbox_host SET "memoryReservedMiB"=2048, "daemonMemoryBudgetMiB"=512, "daemonMaxCpuCount"=1 WHERE id=$1`,
        [host],
      );
      for (const assignment of [
        '"memoryReservedMiB"=-256',
        '"vcpuReserved"=8001',
        '"daemonMemoryBudgetMiB"=513',
        '"daemonMemoryBudgetMiB"=16777472',
        '"daemonMaxCpuCount"=0',
        '"daemonMaxCpuCount"=33',
      ]) {
        await client.query("SAVEPOINT invalid_size");
        const error = await failure(`UPDATE sandbox_host SET ${assignment} WHERE id='${host}'`);
        await client.query("ROLLBACK TO SAVEPOINT invalid_size");
        expect(error.code).toBe("23514");
      }
      for (const table of ["sandbox_template_revision", "sandbox_instance", "sandbox_placement"]) {
        const check = repoChecks.find(
          (item) => item.table === table && item.name.endsWith("_vm_size"),
        );
        expect(check).toBeDefined();
        // Test the exact committed row expression on real PostgreSQL values.
        for (const [cpu, memory, valid] of [
          [1, 1024, true],
          [32, 65536, true],
          [0, 1024, false],
          [33, 1024, false],
          [1, 511, false],
          [1, 513, false],
          [1, 65792, false],
        ] as const) {
          const result = await client.query<{ valid: boolean }>(
            `SELECT (${check!.expression}) AS valid FROM (SELECT $1::int AS "cpuCount", $2::int AS "memoryMiB") AS allocation`,
            [cpu, memory],
          );
          expect(result.rows[0]?.valid).toBe(valid);
        }
        expect(
          (
            await client.query(
              `SELECT 1 FROM pg_constraint WHERE conname=$1 AND conrelid=$2::regclass`,
              [check!.constraint, table],
            )
          ).rows,
        ).toHaveLength(1);
      }
    });
  });
});

it("capacity disk/charge/hold CHECKs enforce bounds independently of current overhead policy", async () => {
  // A revision's floor and default: 1 <= min <= default <= 2048.
  const revision = repoChecks.find((item) => item.name === "sandbox_revision_root_disk")!;
  for (const [min, def, valid] of [
    [0, 32, false],
    [1, 1, true],
    [8, 32, true],
    [32, 8, false],
    [2048, 2048, true],
    [8, 2049, false],
  ] as const) {
    const result = await client.query<{ valid: boolean }>(
      `SELECT (${revision.expression}) AS valid FROM (SELECT $1::int AS "minDiskGiB", $2::int AS "defaultDiskGiB") revision`,
      [min, def],
    );
    expect(result.rows[0]?.valid).toBe(valid);
  }
  for (const table of ["sandbox_instance", "sandbox_placement"]) {
    const check = repoChecks.find(
      (item) =>
        item.table === table &&
        (item.name.endsWith("_disk_size") || item.name.endsWith("_root_disk")),
    );
    expect(check).toBeDefined();
    for (const [disk, valid] of [
      [0, false],
      [1, true],
      [32, true],
      [2048, true],
      [2049, false],
    ] as const) {
      const result = await client.query<{ valid: boolean }>(
        `SELECT (${check!.expression}) AS valid FROM (SELECT $1::int AS "diskGiB") allocation`,
        [disk],
      );
      expect(result.rows[0]?.valid).toBe(valid);
    }
    expect(
      (
        await client.query(
          `SELECT 1 FROM pg_constraint WHERE conname=$1 AND conrelid=$2::regclass`,
          [check!.constraint, table],
        )
      ).rows,
    ).toHaveLength(1);
  }
  const charges = repoChecks.find((item) => item.name === "sandbox_placement_charges")!;
  for (const [memory, cpu, valid] of [
    [null, null, true],
    [null, 1, false],
    [1024, 1, true],
    [1280, 1, true],
    [1088, 1, true],
    [768, 1, false],
    [1280, 2, false],
  ] as const) {
    const result = await client.query<{ valid: boolean }>(
      `SELECT (${charges.expression}) AS valid FROM (SELECT 1024::int AS "memoryMiB", 1::int AS "cpuCount", $1::int AS "chargedMemoryMiB", $2::int AS "chargedVcpu") allocation`,
      [memory, cpu],
    );
    expect(result.rows[0]?.valid).toBe(valid);
  }
});

it("installs every sharing and webhook function and trigger from committed migrations", async () => {
  const functions = (
    await client.query<{ name: string }>(
      `SELECT p.proname AS name FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND starts_with(p.proname, 'wssp_') ORDER BY p.proname`,
    )
  ).rows.map((row) => row.name);
  expect(functions).toEqual([
    "wssp_invite_guard",
    "wssp_member_guard",
    "wssp_pool_guard",
    "wssp_sandbox_stopped_at",
    "wssp_share_guard",
    "wssp_tunnel_client_stop",
    "wssp_webhook_credential_event",
    "wssp_webhook_operation_event",
    "wssp_webhook_pre_ready_states",
    "wssp_webhook_sandbox_event",
  ]);
  const triggers = (
    await client.query<{ name: string; enabled: string }>(
      `SELECT t.tgname AS name, t.tgenabled::text AS enabled FROM pg_trigger t
     JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND NOT t.tgisinternal ORDER BY t.tgname`,
    )
  ).rows;
  expect(triggers).toEqual(
    [
      "wssp_invite_guard",
      "wssp_member_guard",
      "wssp_pool_guard",
      "wssp_sandbox_stopped_at",
      "wssp_share_guard",
      "wssp_tunnel_client_stop",
      "wssp_webhook_credential_event",
      "wssp_webhook_operation_event",
      "wssp_webhook_sandbox_event",
    ].map((name) => ({ name, enabled: "O" })),
  );
});

describe("layered lease policy columns (real PostgreSQL)", () => {
  it("defaults the host ceiling to 24h and leaves pool and member limits unset", async () => {
    const columns = await client.query<{
      table_name: string;
      column_name: string;
      is_nullable: string;
      column_default: string | null;
    }>(
      `SELECT table_name, column_name, is_nullable, column_default FROM information_schema.columns
       WHERE table_schema = 'public' AND (
         (table_name = 'sandbox_host' AND column_name = 'daemonMaxLeaseMs') OR
         (table_name = 'sandbox_pool' AND column_name IN ('maxLeaseMs', 'unlimitedLeaseForShares')) OR
         (table_name = 'sandbox_pool_member' AND column_name = 'maxLeaseMs'))
       ORDER BY table_name, column_name`,
    );
    expect(columns.rows).toEqual([
      {
        table_name: "sandbox_host",
        column_name: "daemonMaxLeaseMs",
        is_nullable: "YES",
        column_default: "86400000",
      },
      {
        table_name: "sandbox_pool",
        column_name: "maxLeaseMs",
        is_nullable: "YES",
        column_default: null,
      },
      {
        table_name: "sandbox_pool",
        column_name: "unlimitedLeaseForShares",
        is_nullable: "NO",
        column_default: "false",
      },
      {
        table_name: "sandbox_pool_member",
        column_name: "maxLeaseMs",
        is_nullable: "YES",
        column_default: null,
      },
    ]);
  });

  it("bounds every finite layer to 5 minutes .. 24 days and the stored deadline to 9999-12-31", async () => {
    for (const [table, name, column] of [
      ["sandbox_host", "sandbox_host_max_lease", "daemonMaxLeaseMs"],
      ["sandbox_pool", "sandbox_pool_max_lease", "maxLeaseMs"],
      ["sandbox_pool_member", "sandbox_member_max_lease", "maxLeaseMs"],
    ] as const) {
      const check = repoChecks.find((item) => item.table === table && item.name === name);
      expect(check).toBeDefined();
      for (const [value, valid] of [
        [null, true],
        [300_000, true],
        [86_400_000, true],
        [2_073_600_000, true],
        [299_999, false],
        [2_073_600_001, false],
        [0, false],
      ] as const) {
        const result = await client.query<{ valid: boolean }>(
          `SELECT (${check!.expression}) AS valid FROM (SELECT $1::int AS "${column}") layer`,
          [value],
        );
        expect(result.rows[0]?.valid, `${name} ${value}`).toBe(valid);
      }
      expect(
        (
          await client.query(
            `SELECT 1 FROM pg_constraint WHERE conname=$1 AND conrelid=$2::regclass`,
            [check!.constraint, table],
          )
        ).rows,
      ).toHaveLength(1);
    }
    const bound = repoChecks.find((item) => item.name === "sandbox_instance_lease_bound")!;
    for (const [value, valid] of [
      [null, true],
      ["2026-01-01 00:00:00.000", true],
      ["9999-12-31 23:59:59.999", true],
      ["10000-01-01 00:00:00.000", false],
    ] as const) {
      const result = await client.query<{ valid: boolean }>(
        `SELECT (${bound.expression}) AS valid FROM (SELECT $1::timestamp(3) AS "leaseExpiresAt") lease`,
        [value],
      );
      expect(result.rows[0]?.valid, String(value)).toBe(valid);
    }
  });
});
