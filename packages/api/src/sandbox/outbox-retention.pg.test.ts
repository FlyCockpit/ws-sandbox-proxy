/**
 * Outbox maintenance on real PostgreSQL: bounded pruning of processed rows
 * of long-deleted, torn-down sandboxes without waiting on locked rows.
 */
import { randomUUID } from "node:crypto";
import type { Prisma } from "@wssp/db";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64) },
}));
const db = await pgTestDatabase();
const { pruneDeletedSandboxOutbox, OUTBOX_RETENTION_DAYS } = await import("./outbox-retention");
afterAll(() => db.close());

const DAY = 86_400_000;
/** Simulated clock: every real timestamp written by the fixtures is old. */
const LATER = () => new Date(Date.now() + (OUTBOX_RETENTION_DAYS + 10) * DAY);

async function sandbox(data: Partial<Prisma.SandboxUncheckedCreateInput> = {}) {
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
      ...data,
    },
  });
  return { userId, sandboxId: row.id };
}
type Sandbox = Awaited<ReturnType<typeof sandbox>>;

async function events(
  s: Sandbox,
  count: number,
  data: Partial<Prisma.OutboxEventUncheckedCreateInput> = {},
) {
  await db.inspect.outboxEvent.createMany({
    data: Array.from({ length: count }, () => {
      const operationId = randomUUID();
      return {
        userId: s.userId,
        aggregateType: "sandbox",
        aggregateId: s.sandboxId,
        eventType: "sandbox.kill_requested",
        payload: { operationId, kind: "sandbox.kill" },
        operationId,
        processedAt: new Date(),
        ...data,
      };
    }),
  });
}
/** The production client, recording each page transaction and each delete. */
function recording() {
  const pages = { count: 0 };
  const deletes: Prisma.OutboxEventDeleteManyArgs[] = [];
  const bound = <T extends object>(target: T, key: PropertyKey) => {
    const value = Reflect.get(target, key);
    return typeof value === "function" ? value.bind(target) : value;
  };
  const client = new Proxy(db.prisma, {
    get(target, key) {
      if (key !== "$transaction") return bound(target, key);
      return (work: (tx: Prisma.TransactionClient) => Promise<unknown>) => {
        pages.count++;
        return target.$transaction((tx) =>
          work(
            new Proxy(tx, {
              get(inner, name) {
                if (name !== "outboxEvent") return bound(inner, name);
                return new Proxy(inner.outboxEvent, {
                  get(delegate, method) {
                    if (method !== "deleteMany") return bound(delegate, method);
                    return (args: Prisma.OutboxEventDeleteManyArgs) => {
                      deletes.push(args);
                      return delegate.deleteMany(args);
                    };
                  },
                });
              },
            }),
          ),
        );
      };
    },
  });
  return { client, pages, deletes };
}
const remaining = (s: Sandbox) =>
  db.inspect.outboxEvent.count({ where: { aggregateId: s.sandboxId } });

describe("prune of processed rows of long-deleted sandboxes", () => {
  // Earlier tests' eligible sandboxes would otherwise share the scan.
  beforeEach(async () => {
    let cursor = "";
    do
      cursor = (await pruneDeletedSandboxOutbox({ client: db.prisma, now: LATER(), cursor }))
        .cursor;
    while (cursor);
  });

  it("deletes only old processed rows of an eligible sandbox, in bounded pages", async () => {
    const s = await sandbox();
    await events(s, 5);
    // Processed inside the window (relative to the simulated clock): kept.
    await events(s, 1, { processedAt: new Date(LATER().getTime() - DAY) });
    const { client, deletes } = recording();
    const result = await pruneDeletedSandboxOutbox({ client, now: LATER(), batch: 2 });
    expect(result.deleted).toBe(5);
    expect(await remaining(s)).toBe(1);
    // ceil(5 / 2) qualified deletes, each by at most `batch` ids.
    const calls = deletes.map((args) => args.where);
    expect(calls).toHaveLength(3);
    for (const where of calls) {
      const ids = where?.id;
      const selectedIds =
        ids && typeof ids === "object" && "in" in ids && Array.isArray(ids.in) ? ids.in : [];
      expect(selectedIds).not.toHaveLength(0);
      expect(selectedIds.length).toBeLessThanOrEqual(2);
      expect(where).toMatchObject({
        userId: s.userId,
        aggregateType: "sandbox",
        aggregateId: s.sandboxId,
        processedAt: { lt: expect.any(Date) },
      });
    }
  });

  it("stops at its page budget mid-sandbox and resumes that sandbox next call", async () => {
    const s = await sandbox();
    await events(s, 5);
    const first = await pruneDeletedSandboxOutbox({
      client: db.prisma,
      now: LATER(),
      batch: 2,
      maxPages: 1,
    });
    expect(first.deleted).toBe(2);
    expect(await remaining(s)).toBe(3);
    // Resumes at (not after) the cut-off sandbox.
    const second = await pruneDeletedSandboxOutbox({
      client: db.prisma,
      now: LATER(),
      batch: 2,
      maxPages: 1,
      cursor: first.cursor,
    });
    expect(second.deleted).toBe(2);
    let cursor = second.cursor;
    let total = first.deleted + second.deleted;
    for (let i = 0; i < 10 && total < 5; i++) {
      const next = await pruneDeletedSandboxOutbox({
        client: db.prisma,
        now: LATER(),
        batch: 2,
        maxPages: 1,
        cursor,
      });
      total += next.deleted;
      cursor = next.cursor;
    }
    expect(total).toBe(5);
    expect(await remaining(s)).toBe(0);
  });

  it.each<[string, (s: Sandbox) => Promise<unknown>]>([
    [
      "not deleted",
      (s) => db.inspect.sandbox.update({ where: { id: s.sandboxId }, data: { state: "STOPPED" } }),
    ],
    [
      "still holding live resources (remnant)",
      (s) =>
        db.inspect.sandbox.update({
          where: { id: s.sandboxId },
          data: { liveResourcesHeld: true },
        }),
    ],
    [
      "written inside the retention window",
      (s) =>
        db.inspect
          .$executeRaw`UPDATE sandbox_instance SET "updatedAt" = ${new Date(LATER().getTime() - DAY)} WHERE id = ${s.sandboxId}`,
    ],
    [
      "with an unsettled operation",
      (s) =>
        db.inspect.sandboxOperation.create({
          data: {
            digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
            ...requestDigestMetadata("KILL_SANDBOX"),

            userId: s.userId,
            sandboxId: s.sandboxId,
            kind: "KILL_SANDBOX",
            state: "UNKNOWN_OUTCOME",
            generation: 1,
            idempotencyKey: randomUUID(),
            requestBodyHash: "a".repeat(64),
          },
        }),
    ],
    ["with an unprocessed outbox row", (s) => events(s, 1, { processedAt: null })],
  ])("keeps every row of a sandbox %s", async (_name, change) => {
    const s = await sandbox();
    await events(s, 3);
    await change(s);
    const before = await remaining(s);
    await pruneDeletedSandboxOutbox({ client: db.prisma, now: LATER() });
    expect(await remaining(s)).toBe(before);
  });

  it("visits at most sandboxLimit sandboxes per call and resumes from the cursor", async () => {
    const a = await sandbox();
    const b = await sandbox();
    await events(a, 2);
    await events(b, 2);
    const [first, second] = [a, b].sort((x, y) => (x.sandboxId < y.sandboxId ? -1 : 1));
    const one = await pruneDeletedSandboxOutbox({
      client: db.prisma,
      now: LATER(),
      sandboxLimit: 1,
    });
    expect(one).toEqual({ deleted: 2, cursor: first!.sandboxId });
    expect(await remaining(first!)).toBe(0);
    expect(await remaining(second!)).toBe(2);
    const two = await pruneDeletedSandboxOutbox({
      client: db.prisma,
      now: LATER(),
      sandboxLimit: 1,
      cursor: one.cursor,
    });
    expect(two.deleted).toBe(2);
    expect(await remaining(second!)).toBe(0);
    // A pruned sandbox is no longer a candidate: the scan wraps to "".
    expect(
      await pruneDeletedSandboxOutbox({ client: db.prisma, now: LATER(), cursor: two.cursor }),
    ).toEqual({ deleted: 0, cursor: "" });
  });

  it("skips a sandbox another transaction holds instead of waiting", async () => {
    const s = await sandbox();
    await events(s, 2);
    let release!: () => void;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    let held = false;
    const holder = db.inspect.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${s.sandboxId} FOR UPDATE`;
        held = true;
        await hold;
      },
      { timeout: 20_000 },
    );
    try {
      await vi.waitFor(() => expect(held).toBe(true));
      const result = await pruneDeletedSandboxOutbox({ client: db.prisma, now: LATER() });
      expect(result.deleted).toBe(0);
      expect(await remaining(s)).toBe(2);
    } finally {
      release();
      await holder;
    }
    expect((await pruneDeletedSandboxOutbox({ client: db.prisma, now: LATER() })).deleted).toBe(2);
  });
});
