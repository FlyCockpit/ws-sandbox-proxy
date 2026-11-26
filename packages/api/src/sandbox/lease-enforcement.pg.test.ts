/**
 * Server lease-policy enforcement on real PostgreSQL: pool create (S1, lease
 * stage and refusal maximum), direct create (S2), setTimeout (S4) including
 * the B2 regression (T2) and the pool-lowering race (T3), and replay (T10).
 */
const leaseEnv = vi.hoisted(() => ({
  SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
  BETTER_AUTH_URL: "http://localhost:3000",
  BETTER_AUTH_SECRET: "lease-enforcement-fixture",
  SANDBOX_MAX_TIMEOUT_MS: 86_400_000 as number | null,
}));
vi.mock("@wssp/env/server", () => ({ env: leaseEnv, ADMIN_EMAILS: new Set() }));
vi.mock("./budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { createSandboxInput, reconnectSandboxInput, setSandboxTimeoutInput } from "./contracts";
import { releaseLiveResourcesOnInventoryProof } from "./host-admission";
import { lockPoolGraph } from "./pool-locks";
import { deleteHost, getHost } from "./services/hosts";
import { deletePool, previewLeaseLowering, removePoolMember, updatePool } from "./services/pools";
import { createSandbox, reconnectSandbox, setSandboxTimeout } from "./services/sandboxes";
import { reconcileSandboxAccess, scanSandboxAccess } from "./sharing-access";
import { poolFixture, poolKey } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
afterEach(() => {
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = 86_400_000;
});

const H1 = 3_600_000;
const H2 = 7_200_000;
const H6 = 21_600_000;
const H7 = 25_200_000;
const F = 2_073_600_000;
const UNLIMITED_END = "9999-12-31T23:59:59.999Z";

const exceeds = (maxTimeoutMs: number) => ({
  code: "BAD_REQUEST",
  data: { code: "lease_exceeds_policy", maxTimeoutMs },
});
const settle = (promise: Promise<unknown>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );

async function ready(id: string) {
  await db.inspect.sandbox.update({ where: { id }, data: { state: "READY" } });
}
function renew(f: Awaited<ReturnType<typeof poolFixture>>, id: string, timeoutMs: number) {
  return setSandboxTimeout(f.owner, { id, idempotencyKey: randomUUID(), timeoutMs });
}

it("S1 pool create: a request over the pool maximum fails with that maximum; a fitting one is accepted", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { maxLeaseMs: H6 } });
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: H7 }),
  ).rejects.toMatchObject(exceeds(H6));
  // A finite deployment refuses 0 before any lock, naming its own maximum.
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: 0 }),
  ).rejects.toMatchObject(exceeds(86_400_000));
  // With every other layer unlimited, the pool maximum is what refuses 0.
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = null;
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMaxLeaseMs: null },
  });
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: 0 }),
  ).rejects.toMatchObject(exceeds(H6));
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = 86_400_000;
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  const accepted = await createSandbox(f.owner, { ...f.input, timeoutMs: H6 });
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: accepted.id } });
  expect(row.leaseExpiresAt!.getTime() - row.createdAt.getTime()).toBeGreaterThan(H6 - 60_000);
});

it("S1 the deployment layer is checked before any lock and included in the maximum", async () => {
  const f = await poolFixture(db);
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = H2;
  await expect(createSandbox(f.owner, { ...f.input, timeoutMs: H6 })).rejects.toMatchObject(
    exceeds(H2),
  );
  // Host ceilings above the deployment never raise the reported maximum.
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = 86_400_000;
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMaxLeaseMs: null },
  });
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: 0 }),
  ).rejects.toMatchObject(exceeds(86_400_000));
});

it("S1 the refusal maximum is the best visible path; hosts hidden from an SDK key never contribute", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMaxLeaseMs: H6 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { daemonMaxLeaseMs: 79_200_000 },
  });
  const request = { ...f.input, timeoutMs: 82_800_000 };
  await expect(createSandbox(f.owner, request)).rejects.toMatchObject(exceeds(79_200_000));
  const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
  await expect(
    createSandbox(key.principal, { ...request, idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject(exceeds(H6));
  // A 7h request lands only on the host that allows it.
  const placed = await createSandbox(f.owner, {
    ...f.input,
    idempotencyKey: randomUUID(),
    timeoutMs: H7,
  });
  expect(placed.sandboxHostId).toBe(f.other.id);
});

it("S1 timeoutMs 0: only when every layer is unlimited; endAt is the far-future value", async () => {
  const f = await poolFixture(db);
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = null;
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: 0 }),
  ).rejects.toMatchObject(exceeds(86_400_000));
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMaxLeaseMs: null },
  });
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: 0 });
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  expect(row.leaseExpiresAt?.toISOString()).toBe(UNLIMITED_END);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: created.id, kind: "CREATE_SANDBOX" },
  });
  expect(operation.leaseTimeoutMs).toBe(0);
  expect(operation.leaseExpiresAtAccepted?.toISOString()).toBe(UNLIMITED_END);
  // A finite request on an unlimited path is bounded only by the 24-day ceiling.
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: F }),
  ).resolves.toMatchObject({ id: expect.any(String) });
});

it("above the 24-day ceiling: dashboard inputs parse and refuse with lease_exceeds_policy, never a generic 400", async () => {
  const f = await poolFixture(db);
  // Every layer unlimited: the finite ceiling itself is the reported maximum.
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = null;
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMaxLeaseMs: null },
  });
  const over = F + 1;
  const create = createSandboxInput.parse({
    ...f.input,
    idempotencyKey: randomUUID(),
    timeoutMs: over,
  });
  await expect(createSandbox(f.owner, create)).rejects.toMatchObject(exceeds(F));
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: 2 ** 40 }),
  ).rejects.toMatchObject(exceeds(F));
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  // A smaller path maximum is reported when it applies (deployment 24 h).
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = 86_400_000;
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: over }),
  ).rejects.toMatchObject(exceeds(86_400_000));
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H1 });
  await ready(created.id);
  const renewal = setSandboxTimeoutInput.parse({
    id: created.id,
    idempotencyKey: randomUUID(),
    timeoutMs: over,
  });
  await expect(setSandboxTimeout(f.owner, renewal)).rejects.toMatchObject(exceeds(86_400_000));
  expect(
    reconnectSandboxInput.safeParse({
      id: created.id,
      idempotencyKey: randomUUID(),
      timeoutMs: over,
    }).success,
  ).toBe(true);
  // Malformed values stay shape errors.
  for (const timeoutMs of [1.5, -1, Number.MAX_SAFE_INTEGER + 1])
    expect(setSandboxTimeoutInput.safeParse({ ...renewal, timeoutMs }).success).toBe(false);
});

it("S2 direct create is bounded by the host ceiling under H", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMaxLeaseMs: H6 },
  });
  const direct = { template: "base", sandboxHostId: f.host.id };
  await expect(
    createSandbox(f.owner, { ...direct, idempotencyKey: randomUUID(), timeoutMs: H7 }),
  ).rejects.toMatchObject(exceeds(H6));
  await expect(
    createSandbox(f.owner, { ...direct, idempotencyKey: randomUUID(), timeoutMs: H6 }),
  ).resolves.toMatchObject({ sandboxHostId: f.host.id });
});

it("T2 (B2 regression): an own-host sandbox keeps its origin pool limit after sharing clears its usage path", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { maxLeaseMs: H6 } });
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H6 });
  await ready(created.id);
  await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, created.id));
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } })).toMatchObject({
    usagePoolId: null,
    usageMemberId: null,
    originPoolId: f.pool.id,
  });
  await expect(renew(f, created.id, H7)).rejects.toMatchObject(exceeds(H6));
  await expect(renew(f, created.id, H2)).resolves.toMatchObject({ id: created.id });
  // The host left the pool: only the host ceiling and the deployment apply.
  await removePoolMember(f.owner, { poolId: f.pool.id, sandboxHostId: created.sandboxHostId! });
  await expect(renew(f, created.id, H7)).resolves.toMatchObject({ id: created.id });
  await expect(renew(f, created.id, 90_000_000)).rejects.toMatchObject(exceeds(86_400_000));
  // Re-adding with the pool deleted still applies only the host ceiling.
  await deletePool(f.owner, { id: f.pool.id });
  await expect(renew(f, created.id, H7)).resolves.toMatchObject({ id: created.id });
});

const G_EXCLUSIVE =
  /^sql:SELECT id FROM sandbox_pool WHERE id = ANY\(\?::text\[\]\) ORDER BY id FOR UPDATE$/;
const G_SHARED =
  /^sql:SELECT id FROM sandbox_pool WHERE id = ANY\(\?::text\[\]\) ORDER BY id FOR SHARE$/;
/** The DB effect of a pool-limit write from another server process: G, then the row. */
function lowerPoolElsewhere(poolId: string, maxLeaseMs: number) {
  return db.prisma.$transaction(async (tx) => {
    await lockPoolGraph(tx, [poolId]);
    await tx.sandboxPool.update({ where: { id: poolId }, data: { maxLeaseMs } });
  });
}

it("T3 setTimeout waits on G for a concurrent pool lowering and is then refused; no deadlock", async () => {
  const f = await poolFixture(db);
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H2 });
  await ready(created.id);
  const parked = db.pauseAt("writer", { after: G_EXCLUSIVE });
  const writer = settle(db.run("writer", () => lowerPoolElsewhere(f.pool.id, H1)));
  await parked.waitReached();
  const renewal = settle(db.run("renew", () => renew(f, created.id, H2)));
  await db.waitUntilBlocked("renew", { by: "writer" });
  parked.release();
  expect(await writer).toMatchObject({ ok: true });
  const outcome = await renewal;
  expect(outcome.ok).toBe(false);
  if (!outcome.ok) expect(outcome.error).toMatchObject(exceeds(H1));
});

it("T3 a renewal holding G shared commits first; the lowering waits for it, then applies", async () => {
  const f = await poolFixture(db);
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H2 });
  await ready(created.id);
  const parked = db.pauseAt("renew", { after: G_SHARED });
  const renewal = settle(db.run("renew", () => renew(f, created.id, H2)));
  await parked.waitReached();
  const writer = settle(db.run("writer", () => lowerPoolElsewhere(f.pool.id, H1)));
  await db.waitUntilBlocked("writer", { by: "renew" });
  parked.release();
  expect(await renewal).toMatchObject({ ok: true });
  expect(await writer).toMatchObject({ ok: true });
  await expect(renew(f, created.id, H2)).rejects.toMatchObject(exceeds(H1));
});

it("T3 through the service: updatePool lowering applies to the next renewal", async () => {
  const f = await poolFixture(db);
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H2 });
  await ready(created.id);
  await updatePool(f.owner, {
    id: f.pool.id,
    slug: f.pool.slug,
    label: f.pool.label,
    maxLeaseMs: H1,
  });
  expect(
    await db.inspect.sandboxPool.findUniqueOrThrow({ where: { id: f.pool.id } }),
  ).toMatchObject({ maxLeaseMs: H1, unlimitedLeaseForShares: false });
  await expect(renew(f, created.id, H2)).rejects.toMatchObject(exceeds(H1));
  // Omitted lease fields are unchanged on update.
  await updatePool(f.owner, { id: f.pool.id, slug: f.pool.slug, label: "Renamed" });
  expect(
    await db.inspect.sandboxPool.findUniqueOrThrow({ where: { id: f.pool.id } }),
  ).toMatchObject({ maxLeaseMs: H1 });
});

it("T10 replay: a create accepted at 6h replays unchanged after the pool limit is lowered", async () => {
  const f = await poolFixture(db);
  const input = { ...f.input, timeoutMs: H6 };
  const first = await createSandbox(f.owner, input);
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { maxLeaseMs: H1 } });
  const replay = await createSandbox(f.owner, input);
  expect(replay.id).toBe(first.id);
  await ready(first.id);
  const renewal = { id: first.id, idempotencyKey: randomUUID(), timeoutMs: H1 };
  await setSandboxTimeout(f.owner, renewal);
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { maxLeaseMs: 300_000 } });
  // The accepted renewal replays even though it now exceeds the pool limit.
  await expect(setSandboxTimeout(f.owner, renewal)).resolves.toMatchObject({ id: first.id });
});

it("preview: counts READY sandboxes on the lease path a lowering would shorten; owner-only", async () => {
  const f = await poolFixture(db);
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H6 });
  await ready(created.id);
  // Own-host row after sharing clears usage still counts through its origin path.
  await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, created.id));
  expect(
    await previewLeaseLowering(f.owner, { scope: "pool", poolId: f.pool.id, maxLeaseMs: H2 }),
  ).toMatchObject({ affected: 1, more: false });
  expect(
    await previewLeaseLowering(f.owner, { scope: "pool", poolId: f.pool.id, maxLeaseMs: H7 }),
  ).toMatchObject({ affected: 0, earliestEnd: null });
  expect(
    await previewLeaseLowering(f.owner, {
      scope: "member",
      poolId: f.pool.id,
      sandboxHostId: created.sandboxHostId!,
      maxLeaseMs: H1,
    }),
  ).toMatchObject({ affected: 1 });
  const other = await poolFixture(db);
  await expect(
    previewLeaseLowering(other.owner, { scope: "pool", poolId: f.pool.id, maxLeaseMs: H1 }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("host view: read-only ceiling and drain empty-by / never", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMaxLeaseMs: null },
  });
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = null;
  await db.inspect.sandboxHost.update({ where: { id: f.other.id }, data: { draining: true } });
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: H2 });
  const view = await getHost(f.owner, { id: created.sandboxHostId! });
  expect(view.lease.ceilingMs).toBeNull();
  expect(view.lease.drain).toMatchObject({ live: 1, unlimited: 0 });
  expect(new Date(view.lease.drain.emptyBy!).getTime()).toBeGreaterThan(Date.now() + H1);
  await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID(), timeoutMs: 0 });
  expect((await getHost(f.owner, { id: created.sandboxHostId! })).lease.drain).toMatchObject({
    live: 2,
    unlimited: 1,
  });
});

/** An unlimited own-host sandbox through the pool (every layer unlimited). */
async function unlimitedOwnHostSandbox() {
  leaseEnv.SANDBOX_MAX_TIMEOUT_MS = null;
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMaxLeaseMs: null },
  });
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: 0 });
  await ready(created.id);
  await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, created.id));
  const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  expect((await row()).leaseExpiresAt?.toISOString()).toBe(UNLIMITED_END);
  expect((await row()).usagePoolId).toBeNull();
  /** The host's STOP result: the live claim is released, the disk stays. */
  const hostStopped = async () => {
    await db.prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.id);
      await releaseLiveResourcesOnInventoryProof(tx, {
        hostId: created.sandboxHostId!,
        ownerId: f.id,
        sandboxId: created.id,
      });
    });
    await db.inspect.sandbox.update({ where: { id: created.id }, data: { state: "STOPPED" } });
  };
  return { f, id: created.id, hostId: created.sandboxHostId!, row, hostStopped };
}

it("review #2: banning the owner STOPS an unlimited own-host sandbox, keeps its disk, starts no grace; unban allows start", async () => {
  const s = await unlimitedOwnHostSandbox();
  await db.inspect.user.update({ where: { id: s.f.id }, data: { banned: true } });
  await scanSandboxAccess();
  const stopped = await s.row();
  expect(stopped.state).toBe("STOPPING");
  expect(stopped.accessGraceUntil).toBeNull();
  expect(stopped.diskReservationHeld).toBe(true);
  expect(
    await db.inspect.sandboxOperation.findMany({
      where: { sandboxId: s.id, kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] } },
      select: { kind: true },
    }),
  ).toEqual([{ kind: "STOP_SANDBOX" }]);
  await s.hostStopped();
  // Still banned: a settled STOPPED row is left alone (no destroy, no grace).
  await scanSandboxAccess();
  expect(await s.row()).toMatchObject({ state: "STOPPED", accessGraceUntil: null });
  await db.inspect.user.update({ where: { id: s.f.id }, data: { banned: false } });
  await scanSandboxAccess();
  expect(await s.row()).toMatchObject({ state: "STOPPED", diskReservationHeld: true });
  expect(
    await db.inspect.sandboxOperation.count({ where: { sandboxId: s.id, kind: "KILL_SANDBOX" } }),
  ).toBe(0);
  // Unbanned, the owner starts it again on its original disk.
  await expect(
    reconnectSandbox(s.f.owner, {
      id: s.id,
      idempotencyKey: randomUUID(),
      mode: "cold",
      timeoutMs: 0,
    }),
  ).resolves.toMatchObject({ operationId: expect.any(String) });
});

it("review #2: deleting the host ends an unlimited own-host sandbox: stop, grace, then destroy", async () => {
  const s = await unlimitedOwnHostSandbox();
  expect(await deleteHost(s.f.owner, { id: s.hostId })).toMatchObject({ pending: true });
  const now = new Date();
  await scanSandboxAccess(() => now);
  const pinned = await s.row();
  expect(pinned.state).toBe("STOPPING");
  expect(pinned.accessGraceUntil).not.toBeNull();
  await s.hostStopped();
  await scanSandboxAccess(() => pinned.accessGraceUntil!);
  expect(
    await db.inspect.sandboxOperation.count({ where: { sandboxId: s.id, kind: "KILL_SANDBOX" } }),
  ).toBe(1);
});

/** A READY sandbox created with `timeoutMs` and `onTimeout`; `stop` settles a host stop. */
async function leasedSandbox(timeoutMs: number, onTimeout: "stop" | "kill") {
  const f = await poolFixture(db);
  const created = await createSandbox(f.owner, {
    ...f.input,
    timeoutMs,
    lifecycle: { onTimeout },
  });
  await ready(created.id);
  await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, created.id));
  const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  const stop = async () => {
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: created.id },
      data: { state: "SUCCEEDED", completedAt: new Date() },
    });
    await db.prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.id);
      await releaseLiveResourcesOnInventoryProof(tx, {
        hostId: created.sandboxHostId!,
        ownerId: f.id,
        sandboxId: created.id,
      });
    });
    await db.inspect.sandbox.update({ where: { id: created.id }, data: { state: "STOPPED" } });
  };
  /** A reconnect at `at`; `timeoutMs` omitted reuses the remembered lease. */
  const connect = async (
    at: Date,
    mode: "warm" | "cold",
    timeoutMs?: number,
    idempotencyKey: string = randomUUID(),
  ) => {
    const accepted = await reconnectSandbox(
      f.owner,
      { id: created.id, idempotencyKey, mode, ...(timeoutMs !== undefined ? { timeoutMs } : {}) },
      () => at,
    );
    const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: accepted.operationId },
    });
    return { row: await row(), operation };
  };
  const start = (at: Date, timeoutMs?: number) => connect(at, "cold", timeoutMs);
  return { f, id: created.id, row, stop, start, connect };
}

it("a start without timeoutMs reuses the create's lease and expiry action; an explicit one wins and is remembered", async () => {
  const s = await leasedSandbox(H2, "stop");
  await s.stop();
  // The CLI hint's `wssp sandbox start <id> --wait`: no lease in the body.
  const at = new Date(Date.now() + 60_000);
  const first = await s.start(at);
  expect(first.row.leaseExpireAction).toBe("STOP");
  expect(first.row.leaseExpiresAt?.getTime()).toBe(at.getTime() + H2);
  expect(first.row.leaseExpiresAtRequested?.getTime()).toBe(at.getTime() + H2);
  expect(first.operation).toMatchObject({ leaseTimeoutMs: H2, leaseExpireActionAccepted: "STOP" });
  expect(first.operation.leaseExpiresAtAccepted?.getTime()).toBe(at.getTime() + H2);
  // An explicit lease wins and becomes the remembered one.
  await ready(s.id);
  await s.stop();
  const later = new Date(at.getTime() + 60_000);
  const explicit = await s.start(later, 600_000);
  expect(explicit.row.leaseExpireAction).toBe("STOP");
  expect(explicit.row.leaseExpiresAt?.getTime()).toBe(later.getTime() + 600_000);
  await ready(s.id);
  await s.stop();
  const last = new Date(later.getTime() + 60_000);
  const again = await s.start(last);
  expect(again.operation).toMatchObject({ leaseTimeoutMs: 600_000 });
  expect(again.row).toMatchObject({ leaseExpireAction: "STOP" });
  expect(again.row.leaseExpiresAt?.getTime()).toBe(last.getTime() + 600_000);
});

it("a renewal is remembered: a later start without timeoutMs uses the renewed lease", async () => {
  const s = await leasedSandbox(H2, "kill");
  await renew(s.f, s.id, 600_000);
  await s.stop();
  const at = new Date(Date.now() + 60_000);
  const started = await s.start(at);
  expect(started.row).toMatchObject({ leaseExpireAction: "DESTROY" });
  expect(started.operation).toMatchObject({ leaseTimeoutMs: 600_000 });
  expect(started.row.leaseExpiresAt?.getTime()).toBe(at.getTime() + 600_000);
  // A start that names a lease after the renewal replaces it again.
  await ready(s.id);
  await s.stop();
  const later = new Date(at.getTime() + 60_000);
  await s.start(later, H1);
  await ready(s.id);
  await s.stop();
  const last = new Date(later.getTime() + 60_000);
  const again = await s.start(last);
  expect(again.row.leaseExpiresAt?.getTime()).toBe(last.getTime() + H1);
});

it("a remembered lease the policy no longer allows is refused, not shortened", async () => {
  const s = await leasedSandbox(H6, "kill");
  await s.stop();
  // The host ceiling drops under the remembered 6 h: nothing is clamped.
  await db.inspect.sandboxHost.updateMany({
    where: { userId: s.f.id },
    data: { daemonMaxLeaseMs: H1 },
  });
  const before = await s.row();
  const at = new Date(Date.now() + 60_000);
  await expect(s.start(at)).rejects.toMatchObject(exceeds(H1));
  expect(await s.row()).toMatchObject({
    state: "STOPPED",
    leaseRevision: before.leaseRevision,
    generation: before.generation,
  });
  const explicit = await s.start(at, H1);
  expect(explicit.row.leaseExpiresAt?.getTime()).toBe(at.getTime() + H1);
});

it("a warm reconnect extends by the remembered lease and never shortens; a shorter explicit one is still remembered", async () => {
  const s = await leasedSandbox(H2, "kill");
  const created = await s.row();
  const at = new Date(Date.now() + 60_000);
  const warm = await s.connect(at, "warm");
  expect(warm.operation).toMatchObject({ leaseTimeoutMs: H2 });
  expect(warm.row.leaseExpiresAt?.getTime()).toBe(
    Math.max(at.getTime() + H2, created.leaseExpiresAt!.getTime()),
  );
  // A shorter explicit warm lease keeps the later deadline in force ...
  const shorter = await s.connect(new Date(at.getTime() + 1000), "warm", 600_000);
  expect(shorter.row.leaseExpiresAt?.getTime()).toBe(warm.row.leaseExpiresAt!.getTime());
  // ... and is the lease the next start without timeoutMs re-arms.
  await s.stop();
  const later = new Date(at.getTime() + 60_000);
  const started = await s.start(later);
  expect(started.row.leaseExpiresAt?.getTime()).toBe(later.getTime() + 600_000);
});

it("an omitted lease and an explicit one are different intents for one idempotency key", async () => {
  const s = await leasedSandbox(H2, "kill");
  const key = randomUUID();
  const at = new Date(Date.now() + 60_000);
  const omitted = await s.connect(at, "warm", undefined, key);
  // The same omitted request replays its receipt, even after the remembered lease changed.
  await s.connect(new Date(at.getTime() + 1000), "warm", 600_000);
  const replay = await s.connect(new Date(at.getTime() + 2000), "warm", undefined, key);
  expect(replay.operation.id).toBe(omitted.operation.id);
  expect(replay.operation.leaseTimeoutMs).toBe(H2);
  await expect(s.connect(at, "warm", H2, key)).rejects.toMatchObject({
    data: { code: "sandbox.idempotency_conflict" },
  });
});

it("the latest lease revision wins, not the latest acceptance clock", async () => {
  const s = await leasedSandbox(H2, "kill");
  await s.stop();
  const at = new Date(Date.now() + 60_000);
  const explicit = await s.start(at, H6);
  // A backward clock step: the later acceptance carries the earlier time.
  await db.inspect.sandboxOperation.update({
    where: { id: explicit.operation.id },
    data: { leaseAcceptedAt: new Date(at.getTime() - 3_600_000) },
  });
  await ready(s.id);
  await s.stop();
  const later = new Date(at.getTime() + 60_000);
  const started = await s.start(later);
  expect(started.row.leaseExpiresAt?.getTime()).toBe(later.getTime() + H6);
});

it("a remembered unlimited lease (0) starts unlimited again", async () => {
  const s = await unlimitedOwnHostSandbox();
  await s.hostStopped();
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: s.id },
    data: { state: "SUCCEEDED", completedAt: new Date() },
  });
  await reconnectSandbox(s.f.owner, { id: s.id, idempotencyKey: randomUUID(), mode: "cold" });
  expect((await s.row()).leaseExpiresAt?.toISOString()).toBe(UNLIMITED_END);
});

it("the remembered-lease lookup is served by its partial index", async () => {
  const plan = await db.prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe("SET LOCAL enable_seqscan = off");
    return tx.$queryRawUnsafe<{ "QUERY PLAN": string }[]>(
      `EXPLAIN SELECT "leaseTimeoutMs" FROM sandbox_mutation_operation
       WHERE "sandboxId" = 'sbx' AND "userId" = 'owner'
         AND kind IN ('CREATE_SANDBOX', 'RECONNECT_SANDBOX', 'RENEW_SANDBOX_LEASE')
         AND "leaseRevisionAccepted" IS NOT NULL AND "leaseTimeoutMs" IS NOT NULL
         AND NOT ("idempotencyKey" LIKE 'lease-policy:%')
       ORDER BY "leaseRevisionAccepted" DESC LIMIT 1`,
    );
  });
  const text = plan.map((row) => row["QUERY PLAN"]).join("\n");
  expect(text).toContain("sandbox_operation_remembered_lease_idx");
  expect(text).not.toContain("Sort");
});
