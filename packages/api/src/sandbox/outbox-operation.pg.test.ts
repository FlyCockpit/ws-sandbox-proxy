/**
 * D5: per-operation outbox lookups read the indexed `operationId` column only;
 * a payload key never matches on its own. Locks keep their id order.
 */
import { randomUUID } from "node:crypto";
import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "ab".repeat(32), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const db = await pgTestDatabase();
const { outboxOperationWhere, outboxOperationSql } = await import("./outbox-operation");
const { resultOutboxLockQuery } = await import("./result-locks");
const { createSandboxOutboxEvent } = await import("./outbox");
afterAll(() => db.close());

async function sandbox() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, name: "Owner", email: `${userId}@example.test` },
  });
  const template = await db.inspect.sandboxTemplate.create({
    data: { userId, slug: randomUUID(), label: "Template" },
  });
  const revision = await db.inspect.sandboxTemplateRevision.create({
    data: {
      userId,
      templateId: template.id,
      revision: 1,
      incusFingerprint: "a".repeat(64),
      architecture: "x86_64",
      manifestDigest: "b".repeat(64),
    },
  });
  const row = await db.inspect.sandbox.create({
    data: {
      userId,
      hostOwnerId: userId,
      templateId: template.id,
      templateRevisionId: revision.id,
      originalSelector: `revision/${revision.id}`,
      originHostId: "gone-host",
      state: "DELETED",
    },
  });
  return { userId, sandboxId: row.id };
}

/** A current row with an indexed operation identity. */
function outboxRow(s: { userId: string; sandboxId: string }, operationId: string, extra = {}) {
  return {
    userId: s.userId,
    aggregateType: "sandbox",
    aggregateId: s.sandboxId,
    eventType: "sandbox.file_stat_requested",
    operationId,
    payload: { operationId, ...extra },
  } satisfies Prisma.OutboxEventUncheckedCreateInput;
}

describe("writers", () => {
  it("createSandboxOutboxEvent copies payload.operationId into the indexed column", async () => {
    const s = await sandbox();
    const operationId = randomUUID();
    await db.prisma.$transaction(async (tx) => {
      // Control kinds skip the instance payload enrichment.
      await createSandboxOutboxEvent(tx, {
        authorizingPrincipal: { kind: "session" },
        userId: s.userId,
        aggregateId: s.sandboxId,
        eventType: "sandbox.operation_cancel_requested",
        payload: { kind: "operation.cancel", operationId },
      });
    });
    const rows = await db.inspect.outboxEvent.findMany({
      where: { aggregateId: s.sandboxId },
      orderBy: { id: "asc" },
      select: { operationId: true, payload: true },
    });
    expect(rows.map((row) => row.operationId).sort()).toEqual([operationId]);
  });
});

describe("lookups", () => {
  it("match the column only when the payload names another operation", async () => {
    const s = await sandbox();
    const op = randomUUID();
    const other = randomUUID();
    const current = await db.inspect.outboxEvent.create({
      data: { ...outboxRow(s, op), operationId: op },
    });
    // Another operation's rows: neither matches `op`.
    await db.inspect.outboxEvent.create({ data: outboxRow(s, other) });
    await db.inspect.outboxEvent.create({ data: { ...outboxRow(s, other), operationId: other } });
    // A row whose column names another operation never matches its payload.
    const columnWins = await db.inspect.outboxEvent.create({
      data: { ...outboxRow(s, op), operationId: other },
    });

    const viaWhere = await db.inspect.outboxEvent.findMany({
      where: { userId: s.userId, aggregateId: s.sandboxId, ...outboxOperationWhere(op) },
      orderBy: { id: "asc" },
      select: { id: true },
    });
    expect(viaWhere.map((row) => row.id)).toEqual([current.id]);

    const viaSql = await db.inspect.$queryRaw<{ id: string }[]>`
      SELECT id FROM sandbox_dispatch_outbox
      WHERE "userId" = ${s.userId} AND "aggregateId" = ${s.sandboxId}
        AND ${outboxOperationSql(op)} ORDER BY id`;
    expect(viaSql.map((row) => row.id)).toEqual([current.id]);
    expect(viaSql.map((row) => row.id)).not.toContain(columnWins.id);
  });

  it("the result suffix lock still takes exactly the operation's rows, in id order, FOR UPDATE", async () => {
    const s = await sandbox();
    const op = randomUUID();
    const mine = [
      await db.inspect.outboxEvent.create({ data: { ...outboxRow(s, op), operationId: op } }),
      await db.inspect.outboxEvent.create({ data: { ...outboxRow(s, op), operationId: op } }),
    ].map((row) => row.id);
    const foreignId = randomUUID();
    const foreign = await db.inspect.outboxEvent.create({
      data: { ...outboxRow(s, foreignId), operationId: foreignId },
    });
    const query = resultOutboxLockQuery(s.userId, {
      sandboxIds: [s.sandboxId],
      operationIds: [op],
    });
    expect(query.sql).toMatch(/ORDER BY id FOR UPDATE$/);
    let release!: () => void;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    let lockedIds: string[] = [];
    const holder = db.prisma.$transaction(async (tx) => {
      lockedIds = (await tx.$queryRaw<{ id: string }[]>(query)).map((row) => row.id);
      await hold;
    });
    try {
      await vi.waitFor(() => expect(lockedIds).toHaveLength(2));
      expect(lockedIds).toEqual([...mine].sort());
      // Held rows refuse NOWAIT from a second session; the other operation's row is free.
      const probe = (id: string) =>
        db.inspect.$transaction((tx) =>
          tx.$queryRaw(
            PrismaValue.sql`SELECT id FROM sandbox_dispatch_outbox WHERE id = ${id} FOR UPDATE NOWAIT`,
          ),
        );
      for (const id of mine) await expect(probe(id)).rejects.toThrow();
      await expect(probe(foreign.id)).resolves.toHaveLength(1);
    } finally {
      release();
      await holder;
    }
  });

  it("plans the per-operation lookup on the operation index", async () => {
    const s = await sandbox();
    const op = randomUUID();
    await db.inspect.outboxEvent.createMany({
      data: Array.from({ length: 2000 }, () => {
        const id = randomUUID();
        return { ...outboxRow(s, id, { path: "/x".repeat(200) }), operationId: id };
      }),
    });
    await db.inspect.outboxEvent.create({ data: { ...outboxRow(s, op), operationId: op } });
    await db.inspect.$executeRaw`ANALYZE sandbox_dispatch_outbox`;
    const plan = await db.inspect.$queryRaw<{ "QUERY PLAN": unknown }[]>(
      PrismaValue.sql`EXPLAIN (FORMAT JSON) SELECT id FROM sandbox_dispatch_outbox
        WHERE "userId" = ${s.userId} AND "aggregateType" = 'sandbox'
          AND "aggregateId" = ${s.sandboxId} AND ${outboxOperationSql(op)}`,
    );
    const conditions: string[] = [];
    const walk = (node: unknown) => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === "object")
        for (const [key, value] of Object.entries(node)) {
          if (key === "Index Cond" && typeof value === "string") conditions.push(value);
          else walk(value);
        }
    };
    walk(plan);
    expect(conditions.some((cond) => cond.includes(`"operationId" = `))).toBe(true);
  });
});
