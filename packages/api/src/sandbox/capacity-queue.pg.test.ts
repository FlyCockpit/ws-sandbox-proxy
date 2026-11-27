import { digestContextSnapshot } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";
import { seedMintSession } from "./testing/resource-fixtures";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "capacity-queue-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("./sharing-budgets", () => ({
  consumePoolCapacityRead: async () => {},
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeLeasePreview: async () => {},
  consumeInviteIssue: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
// The CLI-login fixtures (credentials service) spend procedure budgets.
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { afterAll, describe, expect, it, vi } from "vitest";
import { authenticateSdkKeySecret } from "../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../lib/service-scopes";
import { seedEndpoint } from "../webhooks/testing/fixtures";
import { HEAD_BYPASS_LIMIT } from "./capacity-limits";
import {
  expireCapacityWaits,
  isCapacityWaitingOperation,
  runCapacityQueuePass,
} from "./capacity-queue";
import { getPoolCapacity } from "./capacity-view";
import { leaseNow } from "./lease";
import { setHostDraining } from "./services/hosts";
import { deletePool } from "./services/pools";
import { cancelOperation, createSandbox, killSandbox, stopSandbox } from "./services/sandboxes";
import { createSdkKey, revokeSdkKey } from "./services/sdk-keys";
import { poolFixture, poolKey } from "./testing/pool-fixtures";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

const CHARGE = vmLiveMemoryChargeMiB(1024);
type Fixture = Awaited<ReturnType<typeof poolFixture>>;
const G_LOCK = /SELECT id FROM sandbox_pool WHERE id = ANY\(.*FOR UPDATE/;

async function fill(f: Fixture, hostIds = [f.host.id, f.other.id], reserved = 65536) {
  await db.inspect.sandboxHost.updateMany({
    where: { id: { in: hostIds } },
    data: { memoryReservedMiB: reserved },
  });
}
const wait = (f: Fixture, extra: Record<string, unknown> = {}) => ({
  ...f.input,
  idempotencyKey: randomUUID(),
  waitForCapacityMs: 3_600_000,
  ...extra,
});
async function waitRow(sandboxId: string) {
  return db.inspect.sandboxCapacityWait.findUniqueOrThrow({ where: { sandboxId } });
}
async function sandboxRow(id: string) {
  return db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
}
async function createOp(sandboxId: string) {
  return db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId, kind: "CREATE_SANDBOX" },
  });
}
/** A use grantee with its own exact revision on both fixture hosts. */
async function grantee(f: Fixture) {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Grantee",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const share = await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: id },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: f.host.id,
      slug: `g-${id.slice(0, 8)}`,
      label: "Grantee",
      incusFingerprint: f.revision.incusFingerprint,
    },
  });
  const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
    where: { revisionId: revision.id, hostId: f.host.id },
  });
  const { id: _id, ...copy } = availability;
  await db.inspect.sandboxTemplateAvailability.create({ data: { ...copy, hostId: f.other.id } });
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: id });
  return {
    id,
    owner,
    share,
    revision,
    input: (extra: Record<string, unknown> = {}) => ({
      poolId: f.pool.id,
      template: `revision/${revision.id}`,
      idempotencyKey: randomUUID(),
      waitForCapacityMs: 3_600_000,
      ...extra,
    }),
  };
}

describe("entry", () => {
  it("a waitable refusal enqueues a hostless WAITING sandbox, QUEUED CREATE and wait row; no hold, outbox, placement or lease", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const before = await db.inspect.sandboxHost.findMany({ where: { userId: f.id } });
    const waiting = await createSandbox(f.owner, wait(f));
    expect(waiting).toMatchObject({ state: "WAITING_FOR_CAPACITY", sandboxHostId: null });
    const stored = await sandboxRow(waiting.id);
    expect(stored).toMatchObject({
      sandboxHostId: null,
      hostOwnerId: null,
      originHostId: null,
      currentPlacementId: null,
      usagePoolId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
      leaseExpiresAt: null,
      originPoolId: f.pool.id,
      lastErrorCode: null,
    });
    expect(await createOp(waiting.id)).toMatchObject({
      state: "QUEUED",
      leaseAcceptedAt: null,
      leaseExpiresAtAccepted: null,
    });
    expect(await waitRow(waiting.id)).toMatchObject({ state: "WAITING", lastBlocker: "ram" });
    for (const table of [
      db.inspect.outboxEvent,
      db.inspect.sandboxPlacement,
      db.inspect.sandboxExecutionConfig,
    ])
      expect(await table.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sandboxHost.findMany({ where: { userId: f.id } })).toEqual(before);
    expect(await isCapacityWaitingOperation(f.id, (await createOp(waiting.id)).id)).toBe(true);
  });

  it("direct creates refuse waits (400); waits over policy are refused, never clamped; unlimited only when no layer limits it", async () => {
    const f = await poolFixture(db);
    await expect(
      createSandbox(f.owner, {
        template: "base",
        sandboxHostId: f.host.id,
        idempotencyKey: randomUUID(),
        waitForCapacityMs: 60_000,
      }),
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      // Typed: waits are disabled on a direct target (not a generic 400).
      data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 0 },
    });
    await expect(
      createSandbox(f.owner, wait(f, { waitForCapacityMs: 3_600_001 })),
    ).rejects.toMatchObject({
      data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 3_600_000 },
    });
    await expect(
      createSandbox(f.owner, wait(f, { waitForCapacityMs: "unlimited" })),
    ).rejects.toMatchObject({
      data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 3_600_000 },
    });
    await fill(f);
    await db.inspect.sandboxPool.update({
      where: { id: f.pool.id },
      data: { capacityWaitMaxMs: 60_000 },
    });
    await expect(
      createSandbox(f.owner, wait(f, { waitForCapacityMs: 120_000 })),
    ).rejects.toMatchObject({
      data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 60_000 },
    });
    await db.inspect.sandboxPool.update({
      where: { id: f.pool.id },
      data: { capacityWaitMaxMs: 0 },
    });
    await expect(
      createSandbox(f.owner, wait(f, { waitForCapacityMs: 1_000 })),
    ).rejects.toMatchObject({
      data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 0 },
    });
    expect(await db.inspect.sandboxCapacityWait.count({ where: { userId: f.id } })).toBe(0);
  });

  it("a refusal quotes the effective (pool-lowered) max, whether the create would wait or place now", async () => {
    const f = await poolFixture(db);
    await db.inspect.sandboxPool.update({
      where: { id: f.pool.id },
      data: { capacityWaitMaxMs: 60_000 },
    });
    const effective = { data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 60_000 } };
    // Capacity is free: the same request is refused, never placed and clamped.
    for (const waitForCapacityMs of ["unlimited", 3_600_001, 3_600_000, 120_000])
      await expect(createSandbox(f.owner, wait(f, { waitForCapacityMs }))).rejects.toMatchObject(
        effective,
      );
    await fill(f);
    for (const waitForCapacityMs of ["unlimited", 3_600_001, 120_000])
      await expect(createSandbox(f.owner, wait(f, { waitForCapacityMs }))).rejects.toMatchObject(
        effective,
      );
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
    // Retrying with the quoted max is accepted.
    const waiting = await createSandbox(f.owner, wait(f, { waitForCapacityMs: 60_000 }));
    expect(waiting.state).toBe("WAITING_FOR_CAPACITY");
  });

  it("non-waitable refusals fail immediately (template nowhere, VM larger than every host)", async () => {
    const f = await poolFixture(db);
    await fill(f);
    await expect(createSandbox(f.owner, wait(f, { memoryMiB: 65536 }))).rejects.toMatchObject({
      data: { code: "sandbox.vm_size_unsupported" },
    });
    await db.inspect.sandboxTemplateAvailability.deleteMany({
      where: { revisionId: f.revision.id },
    });
    await expect(createSandbox(f.owner, wait(f))).rejects.toMatchObject({
      data: { code: "sandbox.template_unavailable" },
    });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  });

  it("two creates race for the last slot: without waits one places and one is pool_full; with waits one places and one waits, counters exact", async () => {
    for (const waiting of [false, true]) {
      const f = await poolFixture(db);
      await fill(f, [f.other.id]);
      await fill(f, [f.host.id], 65536 - CHARGE);
      const outcomes = await Promise.allSettled(
        [0, 1].map(() =>
          createSandbox(f.owner, waiting ? wait(f) : { ...f.input, idempotencyKey: randomUUID() }),
        ),
      );
      const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
      expect(host.memoryReservedMiB).toBe(65536);
      expect(host.liveCount).toBe(1);
      const states = outcomes.map((outcome) =>
        outcome.status === "fulfilled" ? outcome.value.state : "rejected",
      );
      if (waiting) expect(states.sort()).toEqual(["REQUESTED", "WAITING_FOR_CAPACITY"]);
      else {
        expect(states.sort()).toEqual(["REQUESTED", "rejected"]);
        const rejected = outcomes.find((outcome) => outcome.status === "rejected");
        expect(rejected).toMatchObject({ reason: { data: { code: "sandbox.pool_full" } } });
      }
    }
  });
});

describe("FIFO and the placer", () => {
  it("seq follows G acquisition order (a parked request enqueues last), and placements follow seq", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const [a, b, c] = [await grantee(f), await grantee(f), await grantee(f)];
    const gate = db.pauseAt("a", { before: G_LOCK });
    const first = db.run("a", () => createSandbox(a.owner, a.input()));
    await gate.waitReached();
    const second = await createSandbox(b.owner, b.input());
    const third = await createSandbox(c.owner, c.input());
    gate.release();
    const last = await first;
    const seqs = await Promise.all(
      [second, third, last].map(async (s) => (await waitRow(s.id)).seq),
    );
    expect(seqs[0]! < seqs[1]! && seqs[1]! < seqs[2]!).toBe(true);
    const placed: string[] = [];
    for (let round = 0; round < 3; round++) {
      await fill(f, [f.host.id], 65536 - CHARGE);
      await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
      for (const s of [second, third, last])
        if ((await sandboxRow(s.id)).state === "REQUESTED" && !placed.includes(s.id))
          placed.push(s.id);
      expect(placed).toHaveLength(round + 1);
    }
    expect(placed).toEqual([second.id, third.id, last.id]);
  });

  it("placement pins the host, starts the lease at placement, writes the outbox and scrubs the intent; lastErrorCode stays NULL", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const waiting = await createSandbox(f.owner, wait(f, { timeoutMs: 600_000, envs: { A: "1" } }));
    await fill(f, [f.host.id], 0);
    const before = new Date();
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    const placed = await sandboxRow(waiting.id);
    expect(placed).toMatchObject({
      state: "REQUESTED",
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      liveResourcesHeld: true,
      lastErrorCode: null,
    });
    expect(placed.leaseExpiresAt!.getTime()).toBeGreaterThanOrEqual(
      before.getTime() + 600_000 - 1000,
    );
    expect(await createOp(waiting.id)).toMatchObject({ state: "QUEUED", leaseTimeoutMs: 600_000 });
    expect(await waitRow(waiting.id)).toMatchObject({ state: "PLACED", intent: null });
    expect(await db.inspect.outboxEvent.count({ where: { aggregateId: waiting.id } })).toBe(1);
    expect(
      (
        await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
          where: { sandboxId: waiting.id },
        })
      ).sandboxOverrides,
    ).toEqual({ A: "1" });
  });

  it("replay while WAITING, after PLACED and after TIMED_OUT returns the same receipt; a different body is idempotency_conflict", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const input = wait(f);
    const first = await createSandbox(f.owner, input);
    expect((await createSandbox(f.owner, input)).id).toBe(first.id);
    await expect(
      createSandbox(f.owner, { ...input, waitForCapacityMs: 120_000 }),
    ).rejects.toMatchObject({ data: { code: "sandbox.idempotency_conflict" } });
    await fill(f, [f.host.id], 0);
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await createSandbox(f.owner, input)).toMatchObject({ id: first.id, state: "REQUESTED" });

    await fill(f);
    const timed = wait(f);
    const entry = await createSandbox(f.owner, timed);
    await db.inspect.sandboxCapacityWait.update({
      where: { sandboxId: entry.id },
      data: { enqueuedAt: new Date(Date.now() - 7_200_000), deadlineAt: new Date(Date.now() - 1) },
    });
    expect(await expireCapacityWaits()).toBe(1);
    expect(await createSandbox(f.owner, timed)).toMatchObject({ id: entry.id, state: "DELETED" });
    await expect(createSandbox(f.owner, { ...timed, timeoutMs: 1_000 })).rejects.toMatchObject({
      data: { code: "sandbox.idempotency_conflict" },
    });
  });
});

describe("timeout, cancel and webhook-visible exits", () => {
  it("timeout: FAILED capacity_wait_timeout with the last blocker, sandbox DELETED with lastErrorCode; placement after it is impossible", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const entry = await createSandbox(f.owner, wait(f));
    await fill(f, [f.host.id], 0);
    // Placer parked before G; the deadline passes while it waits.
    const gate = db.pauseAt("placer", { before: G_LOCK });
    const pass = db.run("placer", () =>
      runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] }),
    );
    await gate.waitReached();
    await db.inspect.sandboxCapacityWait.update({
      where: { sandboxId: entry.id },
      data: { enqueuedAt: new Date(Date.now() - 7_200_000), deadlineAt: new Date(Date.now() - 1) },
    });
    gate.release();
    await pass;
    expect(await waitRow(entry.id)).toMatchObject({ state: "TIMED_OUT", intent: null });
    expect(await sandboxRow(entry.id)).toMatchObject({
      state: "DELETED",
      lastErrorCode: "capacity_wait_timeout",
      liveResourcesHeld: false,
    });
    expect(await createOp(entry.id)).toMatchObject({
      state: "FAILED",
      errorCode: "capacity_wait_timeout",
      failure: { resource: "sandbox", effect: "none", reason: "ram" },
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
    // The opposite order: placed first, then the sweeper is a no-op.
    const placed = await createSandbox(f.owner, wait(f));
    expect(placed.state).toBe("REQUESTED");
    expect(await expireCapacityWaits()).toBe(0);
  });

  it("webhooks: a timed-out wait emits create_failed + destroyed from WAITING_FOR_CAPACITY; a cancelled wait emits only destroyed", async () => {
    const f = await poolFixture(db);
    await seedEndpoint(db.inspect, f.id);
    await fill(f);
    const sandboxEvents = async (sandboxId: string) =>
      (
        await db.inspect.webhookEvent.findMany({
          where: { sandboxId, type: { startsWith: "sandbox." } },
          orderBy: { seq: "asc" },
          select: { type: true, facts: true },
        })
      ).map((event) => ({ type: event.type, facts: event.facts }));

    const timed = await createSandbox(f.owner, wait(f));
    expect((await sandboxRow(timed.id)).state).toBe("WAITING_FOR_CAPACITY");
    await db.inspect.sandboxCapacityWait.update({
      where: { sandboxId: timed.id },
      data: { enqueuedAt: new Date(Date.now() - 7_200_000), deadlineAt: new Date(Date.now() - 1) },
    });
    expect(await expireCapacityWaits()).toBe(1);
    const facts = {
      from: "WAITING_FOR_CAPACITY",
      to: "DELETED",
      generation: 1,
      errorCode: "capacity_wait_timeout",
    };
    expect(await sandboxEvents(timed.id)).toEqual([
      { type: "sandbox.create_failed", facts },
      { type: "sandbox.destroyed", facts },
    ]);

    const killed = await createSandbox(f.owner, wait(f));
    await killSandbox(f.owner, { id: killed.id, idempotencyKey: randomUUID() });
    expect(await sandboxEvents(killed.id)).toEqual([
      {
        type: "sandbox.destroyed",
        facts: { from: "WAITING_FOR_CAPACITY", to: "DELETED", generation: 1, errorCode: null },
      },
    ]);
  });

  it("destroy, stop and operation cancel on a waiting create: CANCELLED, sandbox DELETED with NULL lastErrorCode, receipts SUCCEEDED, replays stable (M2)", async () => {
    const f = await poolFixture(db);
    await fill(f);
    for (const how of ["kill", "stop", "cancel"] as const) {
      const entry = await createSandbox(f.owner, wait(f));
      const key = randomUUID();
      const operation = await createOp(entry.id);
      const act = () =>
        how === "kill"
          ? killSandbox(f.owner, { id: entry.id, idempotencyKey: key })
          : how === "stop"
            ? stopSandbox(f.owner, { id: entry.id, idempotencyKey: key })
            : cancelOperation(f.owner, { operationId: operation.id });
      await act();
      expect(await waitRow(entry.id)).toMatchObject({ state: "CANCELLED", intent: null });
      expect(await sandboxRow(entry.id)).toMatchObject({ state: "DELETED", lastErrorCode: null });
      expect(await createOp(entry.id)).toMatchObject({
        state: "CANCELLED",
        errorCode: "cancelled",
      });
      if (how !== "cancel") {
        expect(
          await db.inspect.sandboxOperation.findFirstOrThrow({
            where: { sandboxId: entry.id, idempotencyKey: key },
          }),
        ).toMatchObject({
          state: "SUCCEEDED",
          kind: how === "kill" ? "KILL_SANDBOX" : "STOP_SANDBOX",
        });
        // Replay of the same teardown after the cancel.
        await expect(act()).resolves.toBeDefined();
      }
      expect(await db.inspect.outboxEvent.count({ where: { aggregateId: entry.id } })).toBe(0);
    }
    // A placed CREATE is still not cancellable.
    await fill(f, [f.host.id], 0);
    const placed = await createSandbox(f.owner, wait(f));
    await expect(
      cancelOperation(f.owner, { operationId: (await createOp(placed.id)).id }),
    ).rejects.toMatchObject({ data: { code: "sandbox.state_conflict" } });
  });

  it("cancel vs placer, both orders: a placer holding G wins and the destroy takes the host path; a cancel holding G wins and the slot goes to the next entry", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const entry = await createSandbox(f.owner, wait(f));
    await fill(f, [f.host.id], 65536 - CHARGE);
    const gate = db.pauseAt("placer", { after: G_LOCK });
    const pass = db.run("placer", () =>
      runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] }),
    );
    await gate.waitReached();
    // Park the destroy just before it takes G, so its transaction is recorded.
    const atG = db.pauseAt("cancel", { before: G_LOCK });
    const destroy = db.run("cancel", () =>
      killSandbox(f.owner, { id: entry.id, idempotencyKey: randomUUID() }),
    );
    await atG.waitReached();
    atG.release();
    await db.waitUntilBlocked("cancel", { by: "placer" });
    gate.release();
    await pass;
    await destroy;
    expect(await waitRow(entry.id)).toMatchObject({ state: "PLACED" });
    expect(await sandboxRow(entry.id)).toMatchObject({ state: "STOPPING" });
    expect(
      await db.inspect.outboxEvent.count({
        where: { aggregateId: entry.id, eventType: "sandbox.kill_requested" },
      }),
    ).toBe(1);

    // Cancel holds G first: the placer then sees CANCELLED and places the next.
    await fill(f);
    const cancelled = await createSandbox(f.owner, wait(f));
    const next = await createSandbox(f.owner, wait(f));
    await fill(f, [f.host.id], 65536 - CHARGE);
    const held = db.pauseAt("cancel2", { after: G_LOCK });
    const cancel = db.run("cancel2", () =>
      killSandbox(f.owner, { id: cancelled.id, idempotencyKey: randomUUID() }),
    );
    await held.waitReached();
    const placerAtG = db.pauseAt("placer2", { before: G_LOCK });
    const pass2 = db.run("placer2", () =>
      runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] }),
    );
    await placerAtG.waitReached();
    placerAtG.release();
    await db.waitUntilBlocked("placer2", { by: "cancel2" });
    held.release();
    await cancel;
    await pass2;
    expect(await waitRow(cancelled.id)).toMatchObject({ state: "CANCELLED" });
    expect(await waitRow(next.id)).toMatchObject({ state: "PLACED" });
  });
});

describe("head protection (§4.3, M4, M6)", () => {
  /** X fits the head only when nearly empty; Y can never fit it (per-VM). */
  async function headFixture() {
    const f = await poolFixture(db);
    const [x, y] = [f.host, f.other];
    await db.inspect.sandboxHost.update({
      where: { id: y.id },
      data: { daemonMemoryBudgetMiB: 16384 },
    });
    await fill(f, [x.id], 40000);
    const head = await createSandbox(f.owner, wait(f, { memoryMiB: 32768 }));
    expect(await waitRow(head.id)).toMatchObject({ state: "WAITING", lastBlocker: "ram" });
    return { f, x, y, head };
  }

  it("non-interfering placements never spend bypasses; 8 interfering ones do, then strict mode reserves X (reserved / enqueue); the head places when X frees", async () => {
    const { f, x, y, head } = await headFixture();
    for (let i = 0; i < 2; i++)
      expect(
        (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId,
      ).toBe(y.id);
    expect((await waitRow(head.id)).bypassCount).toBe(0);
    await fill(f, [y.id], 16384);
    for (let i = 0; i < HEAD_BYPASS_LIMIT; i++)
      expect(
        (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId,
      ).toBe(x.id);
    expect((await waitRow(head.id)).bypassCount).toBe(HEAD_BYPASS_LIMIT);
    await expect(
      createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({
      data: { code: "sandbox.pool_full", reason: "reserved" },
    });
    // The capacity view applies the same gate: X fits nothing for a new
    // arrival and is marked reserved; a grantee's aggregate agrees and
    // still gets no host detail.
    const g = await grantee(f);
    const ownerView = await getPoolCapacity(f.owner, { id: f.pool.id, template: "base" });
    expect(ownerView.fits).toBe(0);
    expect(ownerView.hosts.find((h) => h.id === x.id)).toMatchObject({
      fits: 0,
      excludedBy: "reserved",
      schedulable: true,
    });
    expect(ownerView.hosts.find((h) => h.id === y.id)?.excludedBy).toBeNull();
    const granteeView = await getPoolCapacity(g.owner, {
      id: f.pool.id,
      template: `revision/${g.revision.id}`,
    });
    expect(granteeView.fits).toBe(0);
    expect(granteeView.hosts).toEqual([]);
    const queued = await createSandbox(f.owner, wait(f));
    expect(await waitRow(queued.id)).toMatchObject({ state: "WAITING", lastBlocker: "reserved" });
    // The gate is in the candidate SQL: an unreserved host still serves.
    await fill(f, [y.id], 0);
    const freed = await getPoolCapacity(f.owner, { id: f.pool.id, template: "base" });
    expect(freed.fits).toBe(Math.floor(16384 / CHARGE));
    expect(freed.hosts.find((h) => h.id === x.id)?.excludedBy).toBe("reserved");
    expect(
      (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId,
    ).toBe(y.id);
    await fill(f, [y.id], 16384);
    await fill(f, [x.id], 0);
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await waitRow(head.id)).toMatchObject({ state: "PLACED" });
    expect((await sandboxRow(head.id)).sandboxHostId).toBe(x.id);
  });

  it("a host held only by leases outliving the head's deadline is not head-eligible: it is never reserved (M4)", async () => {
    const { f, x, head } = await headFixture();
    await fill(f, [f.other.id], 16384);
    await fill(f, [x.id], 0);
    // Real sandboxes whose leases outlive the head (far-future) pin X.
    const pinned = [];
    for (let i = 0; i < 2; i++)
      pinned.push(
        await createSandbox(f.owner, {
          ...f.input,
          idempotencyKey: randomUUID(),
          memoryMiB: 16384,
        }),
      );
    await db.inspect.sandbox.updateMany({
      where: { id: { in: pinned.map((s) => s.id) } },
      data: { leaseExpiresAt: new Date("9999-12-31T23:59:59.999Z") },
    });
    // From now on X can never fit the head before its deadline: placements on
    // X spend no bypass and X is never reserved, however many there are.
    const spent = (await waitRow(head.id)).bypassCount;
    for (let i = 0; i < HEAD_BYPASS_LIMIT + 2; i++)
      expect(
        (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId,
      ).toBe(x.id);
    expect((await waitRow(head.id)).bypassCount).toBe(spent);
  });

  it("an entry blocked by connectivity/template (unavailable) gets no head status (M4, 3b template_image_missing)", async () => {
    const f = await poolFixture(db);
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.id,
        sandboxHostId: f.host.id,
        slug: "stale",
        label: "Stale",
        incusFingerprint: `sha256:${"b".repeat(64)}`,
      },
    });
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: revision.id },
      data: { status: "MISSING", verifiedConnectionEpoch: null },
    });
    const blocked = await createSandbox(f.owner, wait(f, { template: `revision/${revision.id}` }));
    expect(await waitRow(blocked.id)).toMatchObject({ lastBlocker: "unavailable" });
    for (let i = 0; i < HEAD_BYPASS_LIMIT + 2; i++)
      await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    expect((await waitRow(blocked.id)).bypassCount).toBe(0);
  });

  it("a head in another pool sharing the host gates this pool's creates on that host (M6)", async () => {
    const { f, x, head } = await headFixture();
    const other = await db.inspect.sandboxPool.create({
      data: { userId: f.id, slug: "p2", label: "P2" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: f.id, hostOwnerId: f.id, poolId: other.id, sandboxHostId: x.id },
    });
    await fill(f, [f.other.id], 16384);
    for (let i = 0; i < HEAD_BYPASS_LIMIT; i++)
      await createSandbox(f.owner, {
        template: "base",
        poolId: other.id,
        idempotencyKey: randomUUID(),
      });
    expect((await waitRow(head.id)).bypassCount).toBe(HEAD_BYPASS_LIMIT);
    await expect(
      createSandbox(f.owner, { template: "base", poolId: other.id, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({ data: { code: "sandbox.pool_full", reason: "reserved" } });
  });

  it("a self-blocked entry (its own share cap) blocks nobody", async () => {
    const f = await poolFixture(db);
    const capped = await grantee(f);
    const free = await grantee(f);
    await db.inspect.share.update({
      where: { id: capped.share.id },
      data: { maxMemoryMiB: CHARGE },
    });
    expect((await createSandbox(capped.owner, capped.input())).state).toBe("REQUESTED");
    const self = await createSandbox(capped.owner, capped.input());
    expect(await waitRow(self.id)).toMatchObject({ lastBlocker: "share_quota" });
    for (let i = 0; i < HEAD_BYPASS_LIMIT + 2; i++)
      expect((await createSandbox(free.owner, free.input())).state).toBe("REQUESTED");
    expect((await waitRow(self.id)).bypassCount).toBe(0);
  });
});

describe("deferred authority (M3) and access loss", () => {
  it.each(["share", "key", "pool", "ban", "hostAllowlist", "revisionAllowlist", "scope"] as const)(
    "%s change while waiting ends the wait FAILED with lastErrorCode",
    async (change) => {
      const f = await poolFixture(db);
      await fill(f);
      const g = await grantee(f);
      const ownerKey = await poolKey(db, f);
      const other = await seedTemplateRevision(db.inspect, {
        data: {
          userId: f.id,
          sandboxHostId: f.host.id,
          slug: `other-${change}`,
          label: "Other",
          incusFingerprint: `sha256:${"c".repeat(64)}`,
        },
      });
      const narrowKey =
        change === "hostAllowlist" || change === "revisionAllowlist" || change === "scope"
          ? await (async () => {
              const created = await createSdkKey(f.owner, {
                name: `narrow-${change}`,
                resourceMode: "ALLOWLIST",
                hostIds: change === "hostAllowlist" ? [] : [f.host.id, f.other.id],
                templateRevisionIds: [change === "revisionAllowlist" ? other.id : f.revision.id],
                poolIds: [f.pool.id],
                scopes: SERVICE_SCOPES.filter(
                  // An allowlist key can hold neither webhooks:write (all-owned only) nor
                  // credentials:use without an allowlisted login; host scopes need a host grant.
                  (scope) =>
                    scope !== "webhooks:write" &&
                    scope !== "credentials:use" &&
                    scope !== "hosts:execute" &&
                    scope !== "hosts:files",
                ),
              });
              return created;
            })()
          : null;
      const principal =
        change === "share" || change === "ban"
          ? g.owner
          : change === "key"
            ? ownerKey.principal
            : change === "pool"
              ? f.owner
              : ownerKey.principal;
      const input = change === "share" || change === "ban" ? g.input() : wait(f);
      const entry = await createSandbox(principal, input);
      expect(entry.state).toBe("WAITING_FOR_CAPACITY");
      if (change === "share") await db.inspect.share.delete({ where: { id: g.share.id } });
      if (change === "key") await revokeSdkKey(f.owner, { id: ownerKey.key.id });
      if (change === "pool") await deletePool(f.owner, { id: f.pool.id });
      if (change === "ban")
        await db.inspect.user.update({ where: { id: g.id }, data: { banned: true } });
      if (narrowKey) {
        // Re-point the waiting entry at the narrowed key (same owner).
        await db.inspect.sandboxCapacityWait.update({
          where: { sandboxId: entry.id },
          data: { authorizingKeyId: narrowKey.key.id },
        });
        if (change === "scope")
          await db.inspect.sdkKey.update({
            where: { id: narrowKey.key.id },
            data: { scopes: ["sandboxes:read", "pools:read"] },
          });
      }
      await fill(f, [f.host.id], 0);
      await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
      const expected = change === "key" ? "credential_inactive" : "access_denied";
      expect(await waitRow(entry.id)).toMatchObject({
        state: "FAILED",
        endReason: expected,
        intent: null,
      });
      expect(await sandboxRow(entry.id)).toMatchObject({
        state: "DELETED",
        lastErrorCode: expected,
      });
      expect(await createOp(entry.id)).toMatchObject({ state: "FAILED", errorCode: expected });
      expect(
        (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
      ).toBe(0);
    },
  );

  it("lease policy: lowered below the request fails lease_exceeds_policy; lowered but fitting places with the lease from placement", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const long = await createSandbox(f.owner, wait(f, { timeoutMs: 7_200_000 }));
    const fits = await createSandbox(f.owner, wait(f, { timeoutMs: 600_000 }));
    await db.inspect.sandboxPool.update({
      where: { id: f.pool.id },
      data: { maxLeaseMs: 3_600_000 },
    });
    await fill(f, [f.host.id], 0);
    const before = Date.now();
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await sandboxRow(long.id)).toMatchObject({
      state: "DELETED",
      lastErrorCode: "lease_exceeds_policy",
    });
    const placed = await sandboxRow(fits.id);
    expect(placed.state).toBe("REQUESTED");
    expect(placed.leaseExpiresAt!.getTime()).toBeGreaterThanOrEqual(before + 600_000 - 1000);
  });

  it("drained hosts keep it waiting (unavailable); undrain places it", async () => {
    const f = await poolFixture(db);
    for (const host of f.hosts) await setHostDraining(f.owner, { id: host.id, draining: true });
    const entry = await createSandbox(f.owner, wait(f));
    expect(await waitRow(entry.id)).toMatchObject({ lastBlocker: "unavailable" });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect((await sandboxRow(entry.id)).state).toBe("WAITING_FOR_CAPACITY");
    await setHostDraining(f.owner, { id: f.host.id, draining: false });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await sandboxRow(entry.id)).toMatchObject({
      state: "REQUESTED",
      sandboxHostId: f.host.id,
    });
  });
});

/**
 * Copies one row of `table` once per override index, replacing the overridden
 * text columns and letting sequence defaults (`seq`) number the copies.
 */
async function cloneRows(table: string, sourceId: string, overrides: Record<string, string[]>) {
  const columns = (
    await db.inspect.$queryRaw<{ column_name: string }[]>`
      SELECT column_name FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = ${table}
        AND (column_default IS NULL OR column_default NOT LIKE 'nextval(%')`
  ).map((c) => c.column_name);
  const names = Object.keys(overrides);
  const quote = (name: string) => `"${name}"`;
  const values = columns.map((c) => (names.includes(c) ? `v.${quote(c)}` : `src.${quote(c)}`));
  const inserted = await db.inspect.$executeRawUnsafe(
    `INSERT INTO ${quote(table)} (${columns.map(quote).join(", ")})
     SELECT ${values.join(", ")} FROM ${quote(table)} src,
       unnest(${names.map((_, i) => `$${i + 2}::text[]`).join(", ")}) AS v(${names.map(quote).join(", ")})
     WHERE src.id = $1`,
    sourceId,
    ...names.map((name) => overrides[name]),
  );
  expect(inserted).toBe(overrides[names[0]!]!.length);
}

describe("queue limits under concurrency", () => {
  it.each(["owner", "key"] as const)(
    "a %s queue limit of 0 is a permanent capacity_queue_full",
    async (scope) => {
      const f = await poolFixture(db);
      await fill(f);
      const key = await poolKey(db, f);
      await db.inspect.sandboxPool.update({
        where: { id: f.pool.id },
        data: scope === "owner" ? { capacityQueuePerOwnerMax: 0 } : { capacityQueuePerKeyMax: 0 },
      });
      await expect(
        createSandbox(scope === "key" ? key.principal : f.owner, wait(f)),
      ).rejects.toMatchObject({
        data: { code: "sandbox.capacity_queue_full", scope, retryable: false },
      });
    },
  );

  it.each(["owner", "key", "pool"] as const)(
    "two concurrent enqueues at the %s limit: exactly one admitted",
    async (scope) => {
      const f = await poolFixture(db);
      await fill(f);
      const key = await poolKey(db, f);
      if (scope === "owner")
        await db.inspect.sandboxPool.update({
          where: { id: f.pool.id },
          data: { capacityQueuePerOwnerMax: 1 },
        });
      if (scope === "key")
        await db.inspect.sandboxPool.update({
          where: { id: f.pool.id },
          data: { capacityQueuePerKeyMax: 1 },
        });
      const principals =
        scope === "pool"
          ? await (async () => {
              // The per-pool ceiling is a constant: prove it with a pre-filled pool.
              const g = [await grantee(f), await grantee(f)];
              return g;
            })()
          : null;
      if (scope === "pool") {
        const { CAPACITY_QUEUE_POOL_CEILING } = await import("./capacity-limits");
        const filler = await createSandbox(f.owner, wait(f));
        const row = await waitRow(filler.id);
        // The other ceiling - 2 waiting entries are SQL-side copies of the
        // filler's real sandbox, operation and wait rows. Inserting ~4k rows per
        // table through the client (serially or batched) costs ~1 ms per row
        // and used most of the 30 s budget on a loaded machine.
        const count = CAPACITY_QUEUE_POOL_CEILING - 2;
        const ids = () => Array.from({ length: count }, () => randomUUID());
        const sandboxIds = ids();
        const operationIds = ids();
        await cloneRows("sandbox_instance", filler.id, {
          id: sandboxIds,
          name: sandboxIds.map((_, i) => `fill-${i}`),
        });
        await cloneRows("sandbox_mutation_operation", row.operationId, {
          id: operationIds,
          sandboxId: sandboxIds,
          idempotencyKey: ids(),
        });
        await cloneRows("sandbox_capacity_wait", row.id, {
          id: ids(),
          sandboxId: sandboxIds,
          operationId: operationIds,
        });
        expect(
          await db.inspect.sandboxCapacityWait.count({
            where: { poolId: f.pool.id, state: row.state },
          }),
        ).toBe(CAPACITY_QUEUE_POOL_CEILING - 1);
      }
      const results = await Promise.allSettled(
        [0, 1].map((i) =>
          scope === "pool"
            ? createSandbox(principals![i]!.owner, principals![i]!.input())
            : createSandbox(scope === "key" ? key.principal : f.owner, wait(f)),
        ),
      );
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      expect(results.find((r) => r.status === "rejected")).toMatchObject({
        // Waiting entries drain: retryable.
        reason: { data: { code: "sandbox.capacity_queue_full", scope, retryable: true } },
      });
    },
  );
});

describe("capacity view disclosure (§6)", () => {
  it("a grantee sees aggregates only, never foreign host ids; the owner sees its hosts; a key's host allowlist excludes hosts from both", async () => {
    const f = await poolFixture(db);
    const g = await grantee(f);
    await fill(f, [f.other.id], 32768);
    const owner = await getPoolCapacity(f.owner, { id: f.pool.id, template: "base" });
    expect(owner.hosts.map((h) => h.id).sort()).toEqual([f.host.id, f.other.id].sort());
    expect(owner.aggregate.free.memoryMiB).toBe(65536 + 32768);
    expect(owner.fits).toBe(Math.floor(65536 / CHARGE) + Math.floor(32768 / CHARGE));
    const shared = await getPoolCapacity(g.owner, {
      id: f.pool.id,
      template: `revision/${g.revision.id}`,
    });
    expect(shared.hosts).toEqual([]);
    expect(JSON.stringify(shared)).not.toContain(f.host.id);
    expect(JSON.stringify(shared)).not.toContain(f.other.id);
    expect(shared.aggregate.free.memoryMiB).toBe(owner.aggregate.free.memoryMiB);
    const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
    const narrowed = await getPoolCapacity(key.principal, { id: f.pool.id, template: "base" });
    expect(narrowed.hosts.map((h) => h.id)).toEqual([f.host.id]);
    expect(narrowed.aggregate.free.memoryMiB).toBe(65536);
    // Owned-host detail needs hosts:read.
    const noHosts = await createSdkKey(f.owner, {
      name: "no-hosts",
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
      poolIds: [],
      scopes: ["pools:read", "templates:read"],
    });
    const principal = await authenticateSdkKeySecret(noHosts.secret);
    const summary = await getPoolCapacity(principal!, { id: f.pool.id, template: "base" });
    expect(summary.hosts).toEqual([]);
    expect(summary.aggregate.free.memoryMiB).toBe(owner.aggregate.free.memoryMiB);
    // An unknown or unowned template is template_not_found, not pool_not_found.
    for (const [viewer, template] of [
      [f.owner, "nope:latest"],
      [g.owner, "base"],
    ] as const)
      await expect(getPoolCapacity(viewer, { id: f.pool.id, template })).rejects.toMatchObject({
        data: { code: "sandbox.template_not_found" },
      });
  });

  it("reports the queue: totals, mine and my oldest position", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const g = await grantee(f);
    await createSandbox(f.owner, wait(f));
    await createSandbox(g.owner, g.input());
    await createSandbox(g.owner, g.input());
    const view = await getPoolCapacity(g.owner, { id: f.pool.id });
    expect(view.queue).toMatchObject({ waiting: 3, mine: 2, myOldestPosition: 2 });
    expect(view.fits).toBeNull();
  });
});

describe("added seed host", () => {
  it("a waiting create on a third, freshly connected host places on hello-equivalent census (wake path unit-tested)", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const entry = await createSandbox(f.owner, wait(f));
    const third = await seedLaunchHost(db.inspect, {
      data: {
        userId: f.id,
        slug: "three",
        label: "three",
        status: "CONNECTED",
        egressEnforcement: true,
        daemonLeasePolicy: true,
      },
    });
    const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
      where: { revisionId: f.revision.id, hostId: f.host.id },
    });
    const { id: _id, ...copy } = availability;
    await db.inspect.sandboxTemplateAvailability.create({ data: { ...copy, hostId: third.id } });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: f.id, hostOwnerId: f.id, poolId: f.pool.id, sandboxHostId: third.id },
    });
    await runCapacityQueuePass(leaseNow, () => false, { hostIds: [third.id] });
    expect(await sandboxRow(entry.id)).toMatchObject({
      state: "REQUESTED",
      sandboxHostId: third.id,
    });
  });
});

/** Clone a waiting entry (its hostless sandbox, QUEUED CREATE and wait row)
 * without admission, e.g. to build queues beyond per-owner limits. */
async function cloneWait(sandboxId: string, overrides: { poolId?: string } = {}) {
  const row = await waitRow(sandboxId);
  const sandbox = await sandboxRow(sandboxId);
  const copy = await db.inspect.sandbox.create({
    data: {
      userId: sandbox.userId,
      templateId: sandbox.templateId,
      templateRevisionId: sandbox.templateRevisionId,
      cpuCount: sandbox.cpuCount,
      memoryMiB: sandbox.memoryMiB,
      diskGiB: sandbox.diskGiB,
      originalSelector: sandbox.originalSelector,
      originPoolId: overrides.poolId ?? sandbox.originPoolId,
      state: "WAITING_FOR_CAPACITY",
    },
  });
  const op = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v1" }),
      ...requestDigestMetadata(),

      userId: sandbox.userId,
      sandboxId: copy.id,
      generation: 1,
      kind: "CREATE_SANDBOX",
      idempotencyKey: randomUUID(),
      requestBodyHash: "fixture",
    },
  });
  const { id: _id, seq: _seq, sandboxId: _s, operationId: _o, intent, ...template } = row;
  return db.inspect.sandboxCapacityWait.create({
    data: {
      ...template,
      ...(overrides.poolId ? { poolId: overrides.poolId } : {}),
      intent: intent ?? {},
      sandboxId: copy.id,
      operationId: op.id,
    },
  });
}

describe("security review regressions", () => {
  it("finding 1: 70 self-blocked entries never starve a fitting entry #71 (rotating scan window)", async () => {
    const f = await poolFixture(db);
    const capped = await grantee(f);
    const later = await grantee(f);
    await db.inspect.share.update({
      where: { id: capped.share.id },
      data: { maxMemoryMiB: CHARGE },
    });
    expect((await createSandbox(capped.owner, capped.input())).state).toBe("REQUESTED");
    const first = await createSandbox(capped.owner, capped.input());
    expect(await waitRow(first.id)).toMatchObject({ lastBlocker: "share_quota" });
    for (let i = 1; i < 70; i++) await cloneWait(first.id);
    // #71 waits only because every host is draining (blocker: unavailable,
    // so it is never a protected head); then capacity returns with no wake.
    await db.inspect.sandboxHost.updateMany({ where: { userId: f.id }, data: { draining: true } });
    const fitting = await createSandbox(later.owner, later.input());
    expect(await waitRow(fitting.id)).toMatchObject({ lastBlocker: "unavailable" });
    await db.inspect.sandboxHost.updateMany({ where: { userId: f.id }, data: { draining: false } });
    let passes = 0;
    while ((await sandboxRow(fitting.id)).state === "WAITING_FOR_CAPACITY" && passes < 3) {
      await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
      passes++;
    }
    expect((await sandboxRow(fitting.id)).state).toBe("REQUESTED");
    expect(
      await db.inspect.sandboxCapacityWait.count({
        where: { poolId: f.pool.id, state: "WAITING", lastBlocker: "share_quota" },
      }),
    ).toBe(70);
  }, 60_000);

  it("finding 2: a deadline that passes while the placer waits for H rolls back the placement and times out", async () => {
    const f = await poolFixture(db);
    await fill(f);
    const entry = await createSandbox(f.owner, wait(f));
    await fill(f, [f.host.id], 0);
    let releaseHolder: () => void = () => {};
    const held = new Promise<void>((resolve) => (releaseHolder = resolve));
    let locked: () => void = () => {};
    const isLocked = new Promise<void>((resolve) => (locked = resolve));
    const holder = db.inspect.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
        locked();
        await held;
      },
      { timeout: 60_000 },
    );
    await isLocked;
    const pass = db.run("placer", () =>
      runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] }),
    );
    await db.waitUntilBlocked("placer");
    await db.inspect.sandboxCapacityWait.update({
      where: { sandboxId: entry.id },
      data: { enqueuedAt: new Date(Date.now() - 7_200_000), deadlineAt: new Date(Date.now() - 1) },
    });
    releaseHolder();
    await holder;
    await pass;
    expect(await waitRow(entry.id)).toMatchObject({ state: "TIMED_OUT" });
    expect(await sandboxRow(entry.id)).toMatchObject({
      state: "DELETED",
      lastErrorCode: "capacity_wait_timeout",
      sandboxHostId: null,
    });
    expect(await db.inspect.sandboxPlacement.count({ where: { sandboxId: entry.id } })).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  });

  it("finding 3: a host whose storage cannot fit the head because of retained roots is not head-eligible (no bypasses, never reserved)", async () => {
    const f = await poolFixture(db);
    const x = f.host;
    await db.inspect.sandboxHost.update({ where: { id: f.other.id }, data: { draining: true } });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: x.id },
      data: { capacityGiB: 1000 },
    });
    const retained = await createSandbox(f.owner, {
      ...f.input,
      idempotencyKey: randomUUID(),
      diskGiB: 960,
    });
    // A stopped sandbox keeps its root: it never frees on its own.
    await db.inspect.sandbox.update({
      where: { id: retained.id },
      data: { state: "STOPPED", liveResourcesHeld: false },
    });
    const head = await createSandbox(f.owner, wait(f, { diskGiB: 50 }));
    expect(await waitRow(head.id)).toMatchObject({ state: "WAITING", lastBlocker: "disk" });
    for (let i = 0; i < HEAD_BYPASS_LIMIT + 2; i++)
      expect(
        (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), diskGiB: 1 }))
          .sandboxHostId,
      ).toBe(x.id);
    expect((await waitRow(head.id)).bypassCount).toBe(0);
  });

  it("finding 4: a strict head in a pool beyond the first 64 sharing the host still reserves it", async () => {
    const f = await poolFixture(db);
    const [x, y] = [f.host, f.other];
    await db.inspect.sandboxHost.update({
      where: { id: y.id },
      data: { daemonMemoryBudgetMiB: 16384 },
    });
    await fill(f, [x.id], 40000);
    await fill(f, [y.id], 16384);
    const seed = await createSandbox(f.owner, wait(f, { memoryMiB: 32768 }));
    const pools: string[] = [];
    for (let i = 0; i < 70; i++) {
      const pool = await db.inspect.sandboxPool.create({
        data: { userId: f.id, slug: `many-${i}`, label: `Many ${i}` },
      });
      await db.inspect.sandboxPoolMember.create({
        data: { userId: f.id, hostOwnerId: f.id, poolId: pool.id, sandboxHostId: x.id },
      });
      pools.push(pool.id);
    }
    const last = [...pools].sort().at(-1)!;
    const heads = new Map<string, string>();
    for (const poolId of pools) heads.set(poolId, (await cloneWait(seed.id, { poolId })).id);
    // Only the head of the pool sorting last by id is strict.
    await db.inspect.sandboxCapacityWait.update({
      where: { id: heads.get(last)! },
      data: { bypassCount: HEAD_BYPASS_LIMIT },
    });
    // The seed head in f.pool is older; take it out so only the far pool gates.
    await killSandbox(f.owner, { id: seed.id, idempotencyKey: randomUUID() });
    await expect(
      createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({ data: { code: "sandbox.pool_full", reason: "reserved" } });
  }, 60_000);
});

describe("security regressions: wrap and head eligibility", () => {
  it("finding 1: tail churn cannot postpone the wrap; a revisited victim places once its cap lifts", async () => {
    const f = await poolFixture(db);
    const front = await grantee(f);
    const attacker = await grantee(f);
    const victim = await grantee(f);
    for (const g of [front, attacker, victim]) {
      await db.inspect.share.update({ where: { id: g.share.id }, data: { maxMemoryMiB: CHARGE } });
      await createSandbox(g.owner, g.input({ waitForCapacityMs: undefined }));
    }
    const seed = await createSandbox(front.owner, front.input());
    for (let i = 1; i < 16; i++) await cloneWait(seed.id);
    const target = await createSandbox(victim.owner, victim.input());
    // A connected daemon keeps reporting; the fixture stamps its hosts' heartbeat
    // and storage report once at seed time, and placement drops a host whose
    // heartbeat is older than HOST_HEARTBEAT_STALE_AFTER_MS (30 s) or whose
    // storage report is older than STORAGE_HEALTH_STALE_MS (15 s). This test
    // runs 10-18 s quietly and 37-40 s on a loaded machine, where the victim
    // stayed WAITING because no host was eligible. Renew both before each
    // pass, as the daemon's own reports would.
    const hostIds = [f.host.id, f.other.id];
    const pass = async () => {
      const now = new Date();
      await db.inspect.sandboxHost.updateMany({
        where: { id: { in: hostIds } },
        data: { lastHeartbeatAt: now },
      });
      await db.inspect.sandboxHostStoragePool.updateMany({
        where: { sandboxHostId: { in: hostIds } },
        data: { reportedAt: now },
      });
      return runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    };
    const churn = async () => {
      const next = await createSandbox(attacker.owner, attacker.input());
      const ids = [next.id];
      for (let i = 1; i < 48; i++) ids.push((await cloneWait(next.id)).sandboxId);
      return ids;
    };
    let rotating = await churn();
    await pass();
    await db.inspect.share.update({ where: { id: victim.share.id }, data: { maxMemoryMiB: null } });
    for (let round = 0; round < 3 && (await waitRow(target.id)).state === "WAITING"; round++) {
      for (const id of rotating)
        await killSandbox(attacker.owner, { id, idempotencyKey: randomUUID() });
      rotating = await churn();
      await pass();
    }
    expect(await waitRow(target.id)).toMatchObject({ state: "PLACED" });
  }, 60_000);

  it("finding 2: a live root with an unlimited (NULL) DESTROY lease stays charged against head eligibility", async () => {
    const f = await poolFixture(db);
    await db.inspect.sandboxPoolMember.updateMany({
      where: { poolId: f.pool.id, sandboxHostId: f.other.id },
      data: { enabled: false },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: f.host.id },
      data: { capacityGiB: 1000 },
    });
    const pinned = await createSandbox(f.owner, {
      sandboxHostId: f.host.id,
      template: "base",
      idempotencyKey: randomUUID(),
      diskGiB: 800,
    });
    await db.inspect.sandbox.update({
      where: { id: pinned.id },
      data: { leaseExpiresAt: null, leaseExpiresAtRequested: null, leaseExpiresAtEffective: null },
    });
    const head = await createSandbox(f.owner, wait(f, { diskGiB: 500 }));
    expect(await waitRow(head.id)).toMatchObject({ lastBlocker: "disk" });
    for (let i = 0; i < HEAD_BYPASS_LIMIT + 1; i++)
      expect(
        (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), diskGiB: 1 }))
          .state,
      ).toBe("REQUESTED");
    expect((await waitRow(head.id)).bypassCount).toBe(0);
  });

  it("finding 3: a stale storage report cannot establish head eligibility", async () => {
    const f = await poolFixture(db);
    await db.inspect.sandboxPoolMember.updateMany({
      where: { poolId: f.pool.id, sandboxHostId: f.other.id },
      data: { enabled: false },
    });
    const storage = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
      where: { sandboxHostId: f.host.id },
    });
    await db.inspect.sandboxHostStoragePool.update({
      where: { id: storage.id },
      data: { capacityGiB: 400 },
    });
    const { id: _id, ...copy } = storage;
    await db.inspect.sandboxHostStoragePool.create({
      data: {
        ...copy,
        marker: randomUUID(),
        name: "stale-large",
        capacityGiB: 1000,
        reportedAt: new Date(Date.now() - 3_600_000),
      },
    });
    const head = await createSandbox(f.owner, wait(f, { diskGiB: 500 }));
    expect(await waitRow(head.id)).toMatchObject({ lastBlocker: "disk" });
    for (let i = 0; i < HEAD_BYPASS_LIMIT + 1; i++)
      expect(
        (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), diskGiB: 1 }))
          .state,
      ).toBe("REQUESTED");
    expect((await waitRow(head.id)).bypassCount).toBe(0);
  });

  it("finding 4: a post-selection reserved refusal commits no bypass for earlier heads", async () => {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.update({ where: { id: f.other.id }, data: { draining: true } });
    await fill(f);
    const first = await createSandbox(f.owner, wait(f, { memoryMiB: 32768 }));
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: f.id, slug: "second", label: "Second" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: f.id, hostOwnerId: f.id, poolId: pool.id, sandboxHostId: f.host.id },
    });
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.id,
        sandboxHostId: f.host.id,
        slug: "second-rev",
        label: "Second revision",
        incusFingerprint: `sha256:${"b".repeat(64)}`,
      },
    });
    const second = await createSandbox(f.owner, {
      poolId: pool.id,
      template: `revision/${revision.id}`,
      idempotencyKey: randomUUID(),
      memoryMiB: 32768,
      waitForCapacityMs: 3_600_000,
    });
    await db.inspect.sandboxCapacityWait.update({
      where: { sandboxId: second.id },
      data: { bypassCount: HEAD_BYPASS_LIMIT },
    });
    // The strict head cannot use the host at selection time…
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: revision.id, hostId: f.host.id },
      data: { status: "MISSING" },
    });
    await fill(f, [f.host.id], 40000);
    const paused = db.pauseAt("late-eligibility", {
      before: /SELECT id FROM sandbox_host WHERE id = .*FOR UPDATE/,
    });
    const request = db.run("late-eligibility", () => createSandbox(f.owner, wait(f)));
    await paused.waitReached();
    // …but can by acceptance, so the placement is refused as reserved.
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: revision.id, hostId: f.host.id },
      data: { status: "AVAILABLE" },
    });
    paused.release();
    const result = await request;
    expect(await waitRow(result.id)).toMatchObject({ lastBlocker: "reserved" });
    expect((await waitRow(first.id)).bypassCount).toBe(0);
    expect(await db.inspect.sandboxPlacement.count({ where: { userId: f.id } })).toBe(0);
  });
});

describe("security regression: pinned member usage", () => {
  it.each(["memory", "vcpu"] as const)(
    "pinned %s member usage outliving the head's deadline makes the contributed host ineligible: no bypasses, never reserved",
    async (resource) => {
      const f = await poolFixture(db);
      await db.inspect.sandboxHost.update({ where: { id: f.other.id }, data: { draining: true } });
      const g = await grantee(f);
      const pool = await db.inspect.sandboxPool.create({
        data: { userId: g.id, slug: "contributed", label: "Contributed" },
      });
      const consent = await db.inspect.share.create({
        data: {
          poolId: pool.id,
          ownerUserId: g.id,
          granteeUserId: f.id,
          canUse: false,
          canContribute: true,
        },
      });
      await db.inspect.sandboxPoolMember.create({
        data: {
          userId: g.id,
          hostOwnerId: f.id,
          poolId: pool.id,
          sandboxHostId: f.host.id,
          shareId: consent.id,
          contributeWitness: true,
          ownHostsOnlyWitness: false,
          ...(resource === "memory" ? { memoryCapPercent: 50 } : { vcpuCapPercent: 25 }),
        },
      });
      const size = resource === "memory" ? { memoryMiB: 16384 } : { cpuCount: 16 };
      const target = { poolId: pool.id, template: `revision/${g.revision.id}` };
      // Its lease (2 h) outlives the head's 1 h wait.
      await createSandbox(g.owner, {
        ...target,
        idempotencyKey: randomUUID(),
        timeoutMs: 7_200_000,
        ...size,
      });
      // Without a wait the same blocker refuses at once, classified retryable:
      // the member's current usage blocks it, not the request alone.
      await expect(
        createSandbox(g.owner, { ...target, idempotencyKey: randomUUID(), ...size }),
      ).rejects.toMatchObject({ data: { code: "sandbox.member_quota", retryable: true } });
      const head = await createSandbox(g.owner, {
        ...target,
        idempotencyKey: randomUUID(),
        waitForCapacityMs: 3_600_000,
        ...size,
      });
      expect(await waitRow(head.id)).toMatchObject({
        state: "WAITING",
        lastBlocker: "member_quota",
      });
      for (let i = 0; i < HEAD_BYPASS_LIMIT + 1; i++)
        expect(
          (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), diskGiB: 1 }))
            .state,
        ).toBe("REQUESTED");
      expect((await waitRow(head.id)).bypassCount).toBe(0);
      // Raising the member cap makes it fit: it places.
      await db.inspect.sandboxPoolMember.updateMany({
        where: { poolId: pool.id, sandboxHostId: f.host.id },
        data: { memoryCapPercent: null, vcpuCapPercent: null },
      });
      await runCapacityQueuePass(leaseNow, () => false, { poolIds: [pool.id] });
      expect(await waitRow(head.id)).toMatchObject({ state: "PLACED" });
    },
    60_000,
  );
});

describe("image distribution (capacity-queue × image-cache merge)", () => {
  const GIB = 1n << 30n;
  const imageFeatures = (leaseFromReady: boolean) => ({
    egressPolicy: true,
    terminal: true,
    image: {
      fetch: true,
      serve: true,
      publish: true,
      capture: true,
      acceptForeign: false,
      leaseFromReady,
      captureStorageMarkers: [],
    },
  });
  /** `host` holds the image (the peer source); `other` can only fetch it. */
  async function imageFixture(leaseFromReady = false) {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: [f.host.id, f.other.id] } },
      data: {
        daemonFeatures: imageFeatures(leaseFromReady),
        imageCacheCapBytes: 100n * GIB,
        imageCacheUsedBytes: 0n,
        imageCacheForeignBytes: 0n,
        imageCacheEpoch: 1,
        connectionEpoch: 1,
      },
    });
    await db.inspect.sandboxTemplateAvailability.deleteMany({
      where: { revisionId: f.revision.id, hostId: f.other.id },
    });
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: f.revision.id, hostId: f.host.id },
      data: { sizeBytes: 2n * GIB, imageFormat: "unified" },
    });
    return f;
  }

  it("an offline peer source is a waitable 'unavailable' blocker (fetchable hosts count as statically feasible); the create places once the source returns", async () => {
    const f = await imageFixture();
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "DISCONNECTED" },
    });
    const waiting = await createSandbox(f.owner, wait(f));
    expect(waiting).toMatchObject({ state: "WAITING_FOR_CAPACITY" });
    expect(await waitRow(waiting.id)).toMatchObject({ lastBlocker: "unavailable" });
    // Without a wait the same request is refused as a missing image.
    await expect(
      createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({ data: { code: "sandbox.template_image_missing" } });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "CONNECTED", lastHeartbeatAt: new Date() },
    });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await sandboxRow(waiting.id)).toMatchObject({ state: "REQUESTED" });
  });

  it("a host that already has the image ranks before an emptier host that would fetch it (after the own-host tier)", async () => {
    const f = await imageFixture();
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { memoryReservedMiB: 32768 },
    });
    const placed = await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    expect(placed.sandboxHostId).toBe(f.host.id);
    // Full source: the fetching host places, with planned fetch bytes.
    await fill(f, [f.host.id]);
    const fetched = await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    expect(fetched.sandboxHostId).toBe(f.other.id);
    const placement = await db.inspect.sandboxPlacement.findFirstOrThrow({
      where: { sandboxId: fetched.id },
    });
    expect(placement.imageFetchBytes).toBe(2n * GIB);
  });

  it("a queued placement on a lease-from-READY host writes the provisional lease and hides the public deadline", async () => {
    const f = await imageFixture(true);
    await fill(f);
    const waiting = await createSandbox(f.owner, wait(f, { timeoutMs: 600_000 }));
    await fill(f, [f.host.id], 0);
    const before = Date.now();
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    const placed = await sandboxRow(waiting.id);
    expect(placed).toMatchObject({ state: "REQUESTED", leasePendingReady: true });
    // Provisional backstop: placement + timeout + the provisioning maximum.
    expect(placed.leaseExpiresAt!.getTime()).toBeGreaterThan(before + 600_000 + 60_000);
    expect(await createOp(waiting.id)).toMatchObject({ leaseFromReady: true });
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: waiting.id },
    });
    expect(event.payload).toMatchObject({ leaseFromReadyMs: 600_000 });
  });

  it("a sandbox waiting for capacity cannot be captured (state_conflict)", async () => {
    const f = await imageFixture();
    await fill(f);
    const waiting = await createSandbox(f.owner, wait(f));
    const { captureSandbox } = await import("./image-store/captures");
    await expect(
      captureSandbox(f.owner, { id: waiting.id, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({ data: { code: "sandbox.state_conflict" } });
  });
});

describe("CLI logins at queue entry (E1-B-05 scope)", () => {
  const CREDENTIAL_CAPABILITY = {
    files: true,
    env: true,
    proxy: false,
    sealedReturn: true,
    checkpoint: true,
    specTransfer: true,
    maxBundleBytes: 4_823_129,
    returnKeyEpoch: 0,
  };

  it("a waitable create naming a held exclusive instance is admitted, waits while the slot is held, and is placed once it frees", async () => {
    const saved = {
      key: process.env.DATA_ENCRYPTION_KEY,
      enabled: process.env.CREDENTIALS_ENABLED,
    };
    process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
    process.env.CREDENTIALS_ENABLED = "true";
    try {
      const service = await import("../credentials/service");
      const f = await poolFixture(db);
      for (const host of f.hosts) {
        const row = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } });
        await db.inspect.sandboxHost.update({
          where: { id: host.id },
          data: {
            daemonFeatures: {
              ...(row.daemonFeatures as Record<string, unknown> | null),
              credentials: CREDENTIAL_CAPABILITY,
            },
          },
        });
      }
      const slug = `tool-${randomUUID().slice(0, 8)}`;
      const definition = await service.createDefinition(f.owner, {
        document: {
          schemaVersion: 1,
          id: slug,
          displayName: "Tool",
          login: { command: "tool login", method: "device-code" },
          credentials: {
            files: { required: [".config/tool"], optional: [], exclude: [] },
            sharing: "exclusive",
          },
        },
      });
      const login = await service.createLogin(f.owner, { name: slug, definitionId: definition.id });
      const account = await service.createAccount(f.owner, { credentialId: login.id });
      const instance = await service.createInstance(f.owner, {
        credentialId: login.id,
        accountId: account.id,
      });
      await service.writeValue(f.owner, {
        credentialId: login.id,
        instanceId: instance.id,
        files: [
          { path: ".config/tool", kind: "dir" },
          { path: ".config/tool/token", contentBase64: Buffer.from("v").toString("base64") },
        ],
      });
      // Another sandbox holds the exclusive instance now.
      const holder = await db.inspect.sandbox.create({
        data: {
          userId: f.id,
          templateId: f.revision.templateId,
          templateRevisionId: f.revision.id,
          originalSelector: `revision/${f.revision.id}`,
          originHostId: f.host.id,
          sandboxHostId: f.host.id,
          hostOwnerId: f.id,
          state: "READY",
        },
        select: { id: true },
      });
      const held = await db.inspect.credentialLease.create({
        data: {
          userId: f.id,
          credentialId: login.id,
          accountId: account.id,
          instanceId: instance.id,
          sandboxId: holder.id,
          operationId: "op-holder",
          kind: "WORKLOAD",
          exclusive: true,
          state: "ACTIVE",
          hostId: f.host.id,
        },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instance.id },
        data: { activeLeases: 1 },
      });
      const request = { credentials: [{ credentialId: login.id, instanceId: instance.id }] };
      // A create that cannot wait still gets the login refusal before placement.
      await expect(
        createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), ...request }),
      ).rejects.toMatchObject({ data: { code: "credential.in_use" } });
      await fill(f);
      const waiting = await createSandbox(f.owner, wait(f, request));
      expect(waiting).toMatchObject({ state: "WAITING_FOR_CAPACITY" });
      expect(await waitRow(waiting.id)).toMatchObject({ state: "WAITING" });
      // Capacity frees first: the claim at placement finds the slot held and
      // the create keeps waiting, with nothing claimed.
      await fill(f, [f.host.id], 0);
      await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
      expect(await waitRow(waiting.id)).toMatchObject({ state: "WAITING" });
      expect(await db.inspect.credentialLease.count({ where: { sandboxId: waiting.id } })).toBe(0);
      // The holder lets go: the next pass places the create and claims the slot.
      await db.inspect.credentialLease.update({
        where: { id: held.id },
        data: { state: "RELEASED", releasedAt: new Date() },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instance.id },
        data: { activeLeases: 0 },
      });
      await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
      expect(await waitRow(waiting.id)).toMatchObject({ state: "PLACED" });
      expect(
        await db.inspect.credentialLease.findFirstOrThrow({
          where: { sandboxId: waiting.id },
          select: { instanceId: true, state: true },
        }),
      ).toEqual({ instanceId: instance.id, state: "RESERVED" });
    } finally {
      if (saved.key === undefined) delete process.env.DATA_ENCRYPTION_KEY;
      else process.env.DATA_ENCRYPTION_KEY = saved.key;
      if (saved.enabled === undefined) delete process.env.CREDENTIALS_ENABLED;
      else process.env.CREDENTIALS_ENABLED = saved.enabled;
    }
  });
});
