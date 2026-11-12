vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "pool-placement-timezone-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
import { hostDatabaseNow } from "./relay-fence";
import { createSandbox } from "./services/sandboxes";
import { poolFixture } from "./testing/pool-fixtures";

// This file's clone has a non-UTC database default TimeZone. Prisma stores
// DateTime as UTC wall time in `timestamp` columns and its pg adapter reads a
// timestamptz by replacing (not converting) the session offset, so a database
// clock read or a SQL comparison against clock_timestamp() would be hours off
// in a non-UTC session. The client forces UTC sessions (client.ts); the clock
// reads are also explicitly UTC, proven below under SET LOCAL.
const db = await pgTestDatabase();
afterAll(() => db.close());

async function withSessionTimeZone(zone: string) {
  if (!/^[A-Za-z_/+-]+$/.test(zone)) throw new Error("unexpected zone");
  await db.inspect.$executeRawUnsafe(`ALTER DATABASE ${db.name} SET "TimeZone" = '${zone}'`);
}

beforeAll(async () => {
  await withSessionTimeZone("America/Los_Angeles");
});

it("hostDatabaseNow is the true instant under a non-UTC session TimeZone", async () => {
  for (const zone of ["America/Los_Angeles", "Pacific/Kiritimati"]) {
    await withSessionTimeZone(zone);
    await db.prisma.$transaction(async (tx) => {
      // A fresh pool connection may predate the ALTER; pin the zone here too.
      await tx.$executeRawUnsafe(`SET LOCAL "TimeZone" = '${zone}'`);
      const [{ zone: session }] = await tx.$queryRaw<
        { zone: string }[]
      >`SELECT current_setting('TimeZone') AS zone`;
      expect(session).toBe(zone);
      const before = Date.now();
      const now = await hostDatabaseNow(tx);
      expect(Math.abs(now.getTime() - before)).toBeLessThan(60_000);
    });
  }
  await withSessionTimeZone("America/Los_Angeles");
});

it("pool placement admits a freshly heartbeating host under a non-UTC database TimeZone", async () => {
  const f = await poolFixture(db);
  const [{ zone }] = await db.prisma.$queryRaw<
    { zone: string }[]
  >`SELECT current_setting('TimeZone') AS zone`;
  // The client forces UTC sessions despite the non-UTC database default.
  expect(zone).toBe("UTC");
  // The host heartbeat window and storage freshness are compared against the
  // database clock; an hours-off clock calls the fresh host stale. An
  // expired ban (one hour ago) must also read as expired, not still active.
  await db.inspect.user.update({
    where: { id: f.id },
    data: { banned: true, banExpires: new Date(Date.now() - 3_600_000) },
  });
  const created = await createSandbox(f.owner, f.input);
  expect([f.host.id, f.other.id]).toContain(created.sandboxHostId);
});
