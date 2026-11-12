/**
 * Lease pull-in on real PostgreSQL (§3.4): the warm re-arm pull-in and its
 * revision order (T5, M2/N1), the sweep keyed on the enforced deadline with
 * the in-flight skip and retry (T6, M3) under a non-UTC session, pull-in vs a
 * user renewal and non-READY rows (T7), the lock-order matrix (T8), the
 * unlimited lifecycle (T9) and the system dispatch path (T11, M4).
 */
import {
  acknowledgeFixtureExecutionConfigs,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";

const settings = vi.hoisted(() => ({ max: 86_400_000 as number | null }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "lease-pull-in-fixture",
    get SANDBOX_MAX_TIMEOUT_MS() {
      return settings.max;
    },
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
vi.mock("@wssp/mailer", () => ({
  sendEmail: vi.fn(async () => {}),
  renderPoolAccessNotice: () => ({ subject: "notice", html: "notice" }),
}));
const relay = vi.hoisted(() => ({
  dispatchOperation: vi.fn(async (): Promise<string> => "sent"),
}));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: relay.dispatchOperation,
    captureHostDispatchCredential: vi.fn(),
  },
}));

const db = await pgTestDatabase();
const { allOwnedPoolKey, poolFixture } = await import(
  "../../../../packages/api/src/sandbox/testing/pool-fixtures"
);
const { revokeSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { createSandbox, killSandbox, reconnectSandbox, setSandboxTimeout } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { updatePool, updatePoolMember } = await import(
  "../../../../packages/api/src/sandbox/services/pools"
);
const { pullInSandboxLease, scanLeasePolicy } = await import("@wssp/api/sandbox/lease-pull-in");
const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
const { systemDispatchAllowed } = await import("@wssp/api/sandbox/outbox");
const { reconcileSandboxAccess } = await import("@wssp/api/sandbox/sharing-access");
const { processSandboxOutboxBatch: processOutbox } = await import("./outbox-processor.js");
const { convergeInventoryEntry } = await import("./inventory-reconcile.js");

const H1 = 3_600_000;
const H2 = 7_200_000;
const H20 = 72_000_000;
const UNLIMITED_END = "9999-12-31T23:59:59.999Z";
const owners: string[] = [];

/**
 * M3/minor 4: every policy time comparison binds a JS Date, so a non-UTC
 * time zone must not move it. The database default set here no longer
 * reaches client sessions: createPrismaClient forces `TimeZone=UTC` in each
 * startup packet (client.pg.test.ts), so the sweep runs under a non-UTC
 * database default with UTC sessions.
 */
async function sessionTimeZone(zone: string | null) {
  const name = new URL(db.url).pathname.slice(1);
  await db.inspect.$executeRawUnsafe(
    zone === null
      ? `ALTER DATABASE "${name}" RESET timezone`
      : `ALTER DATABASE "${name}" SET timezone TO '${zone}'`,
  );
  await db.prisma.$disconnect();
}
afterAll(() => db.close());
afterEach(async () => {
  settings.max = 86_400_000;
  relay.dispatchOperation.mockReset();
  relay.dispatchOperation.mockResolvedValue("sent");
  await db.inspect.outboxEvent.updateMany({
    where: { userId: { in: owners }, processedAt: null },
    data: { processedAt: new Date() },
  });
});

/** A READY pool sandbox whose 20h lease the host has acknowledged. */
async function readySandbox(timeoutMs = H20) {
  const f = await poolFixture(db);
  owners.push(f.id);
  let now = Date.now();
  const clock = () => new Date(now);
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs }, clock);
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: {
      state: "READY",
      leaseRevisionEffective: row.leaseRevision,
      leaseExpiresAtEffective: row.leaseExpiresAt,
      leaseExpireActionEffective: row.leaseExpireAction,
    },
  });
  return {
    f,
    id: created.id,
    clock,
    advance: (ms: number) => {
      now += ms;
    },
    nowMs: () => now,
    row: () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } }),
    ops: (kind: "RENEW_SANDBOX_LEASE" | "RECONNECT_SANDBOX") =>
      db.inspect.sandboxOperation.findMany({
        where: { sandboxId: created.id, kind },
        orderBy: { leaseRevisionAccepted: "asc" },
      }),
  };
}
const eventFor = async (operationId: string) =>
  (
    await db.inspect.outboxEvent.findFirstOrThrow({
      where: { payload: { path: ["operationId"], equals: operationId } },
    })
  ).payload as Record<string, unknown> & {
    lease: { revision: number; deadlineUnixMs: number; action: "stop" | "destroy" };
    authorizingPrincipal: { kind: string };
  };
const settle = (promise: Promise<unknown>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );

it("T5 (M2/N1): a warm re-arm over the limit is pulled in at the end of the same transaction; reconnect r+1, renew r+2", async () => {
  const s = await readySandbox();
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H2 } });
  // A pull-in commits but the host has not acknowledged it yet.
  expect(await scanLeasePolicy(s.clock)).toBe(1);
  const before = await s.row();
  expect(before.leaseExpiresAtEffective!.getTime()).toBeGreaterThan(s.nowMs() + H2);
  await reconnectSandbox(
    s.f.owner,
    { id: s.id, idempotencyKey: randomUUID(), mode: "warm", timeoutMs: H1 },
    s.clock,
  );
  const [reconnect] = await s.ops("RECONNECT_SANDBOX");
  const renewals = await s.ops("RENEW_SANDBOX_LEASE");
  const last = renewals.at(-1)!;
  // The reconnect re-armed to the long effective deadline (journal refuses a
  // shortening connect) and its dispatch lease carries exactly its revision.
  expect(reconnect!.leaseRevisionAccepted).toBe(before.leaseRevision + 1);
  expect(reconnect!.leaseExpiresAtAccepted).toEqual(before.leaseExpiresAtEffective);
  expect((await eventFor(reconnect!.id)).lease.revision).toBe(reconnect!.leaseRevisionAccepted);
  // The inline pull-in is the next revision and only shortens.
  expect(last.idempotencyKey).toBe(`lease-policy:${s.id}:1:${reconnect!.leaseRevisionAccepted}`);
  expect(last.leaseRevisionAccepted).toBe(reconnect!.leaseRevisionAccepted! + 1);
  expect(last.leaseExpiresAtAccepted!.getTime()).toBeLessThanOrEqual(s.nowMs() + H2);
  expect(last.authorizingKeyId).toBeNull();
  const renewEvent = await eventFor(last.id);
  expect(renewEvent.lease.revision).toBe(last.leaseRevisionAccepted);
  expect(renewEvent.authorizingPrincipal).toEqual({ kind: "system" });
  expect((await s.row()).leaseRevision).toBe(last.leaseRevisionAccepted);
  // A re-arm already within the limit adds no pull-in.
  const settled = await s.row();
  await db.inspect.sandbox.update({
    where: { id: s.id },
    data: {
      leaseRevisionEffective: settled.leaseRevision,
      leaseExpiresAtEffective: settled.leaseExpiresAt,
    },
  });
  await reconnectSandbox(
    s.f.owner,
    { id: s.id, idempotencyKey: randomUUID(), mode: "warm", timeoutMs: H1 },
    s.clock,
  );
  expect(await s.ops("RENEW_SANDBOX_LEASE")).toHaveLength(renewals.length);
});

it("T6 (M3): the sweep keys on the enforced deadline, skips an in-flight pull-in and retries a failed one", async () => {
  const s = await readySandbox();
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H2 } });
  await sessionTimeZone("Pacific/Chatham");
  try {
    await sweepScenario(s);
  } finally {
    await sessionTimeZone(null);
  }
});

async function sweepScenario(s: Awaited<ReturnType<typeof readySandbox>>) {
  const [tz] = await db.prisma.$queryRaw<{ TimeZone: string }[]>`SHOW TIME ZONE`;
  expect(tz?.TimeZone).toBe("UTC");
  // Pool hints match the lease path pool; an unrelated hint finds nothing.
  expect(await scanLeasePolicy(s.clock, () => false, new Set(["unrelated"]))).toBe(0);
  expect(await scanLeasePolicy(s.clock, () => false, new Set([s.f.pool.id]))).toBe(1);
  const [first] = await s.ops("RENEW_SANDBOX_LEASE");
  expect(first!.leaseExpiresAtAccepted!.getTime()).toBe(s.nowMs() + H2);
  // Requested is short now, but the host still enforces 20h: in flight → skip.
  expect(await scanLeasePolicy(s.clock)).toBe(0);
  await db.inspect.sandboxOperation.update({
    where: { id: first!.id },
    data: { state: "FAILED", completedAt: new Date() },
  });
  s.advance(60_000);
  expect(await scanLeasePolicy(s.clock)).toBe(1);
  const retried = (await s.ops("RENEW_SANDBOX_LEASE")).at(-1)!;
  expect(retried.id).not.toBe(first!.id);
  expect(retried.leaseRevisionAccepted).toBe(first!.leaseRevisionAccepted! + 1);
  // Never lengthens the shorter pending request.
  expect(retried.leaseExpiresAtAccepted).toEqual(first!.leaseExpiresAtAccepted);
  // Once acknowledged, nothing repeats.
  await db.inspect.sandbox.update({
    where: { id: s.id },
    data: {
      leaseRevisionEffective: retried.leaseRevisionAccepted,
      leaseExpiresAtEffective: retried.leaseExpiresAtAccepted,
    },
  });
  expect(await scanLeasePolicy(s.clock)).toBe(0);
}

it("T7: pull-in and a user renewal serialize on H/S; exactly one revision per commit, and non-READY rows are never pulled in", async () => {
  const s = await readySandbox();
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H2 } });
  const parked = db.pauseAt("renew", { after: "sandbox.updateMany" });
  const renewal = settle(
    db.run("renew", () =>
      setSandboxTimeout(
        s.f.owner,
        { id: s.id, idempotencyKey: randomUUID(), timeoutMs: H1 },
        s.clock,
      ),
    ),
  );
  await parked.waitReached();
  const pull = settle(db.run("pull", () => pullInSandboxLease(s.id, s.clock)));
  await db.waitUntilBlocked("pull", { by: "renew" });
  parked.release();
  expect(await renewal).toMatchObject({ ok: true });
  // The user's 1h request is in flight and within the limit: no pull-in.
  expect(await pull).toEqual({ ok: true, value: false });
  const row = await s.row();
  expect(row.leaseRevision).toBe(2);
  expect(row.leaseExpiresAt!.getTime()).toBe(s.nowMs() + H1);
  expect(
    (await s.ops("RENEW_SANDBOX_LEASE")).filter((o) =>
      o.idempotencyKey.startsWith("lease-policy:"),
    ),
  ).toHaveLength(0);
  for (const state of ["STOPPING", "STOPPED", "ERROR"] as const) {
    await db.inspect.sandbox.update({
      where: { id: s.id },
      data: { state, leaseExpiresAt: new Date(s.nowMs() + H20) },
    });
    expect(await pullInSandboxLease(s.id, s.clock)).toBe(false);
  }
});

it("T7: a pull-in holding S commits first; the user renewal waits and then takes the next revision", async () => {
  const s = await readySandbox();
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H2 } });
  const parked = db.pauseAt("pull", {
    after: /^sql:SELECT id FROM sandbox_instance WHERE id = \? AND "userId" = \? FOR UPDATE$/,
  });
  const pull = settle(db.run("pull", () => pullInSandboxLease(s.id, s.clock)));
  await parked.waitReached();
  const renewal = settle(
    db.run("renew", () =>
      setSandboxTimeout(
        s.f.owner,
        { id: s.id, idempotencyKey: randomUUID(), timeoutMs: H1 },
        s.clock,
      ),
    ),
  );
  await db.waitUntilBlocked("renew", { by: "pull" });
  parked.release();
  expect(await pull).toEqual({ ok: true, value: true });
  expect(await renewal).toMatchObject({ ok: true });
  const revisions = (await s.ops("RENEW_SANDBOX_LEASE")).map((o) => o.leaseRevisionAccepted);
  expect(revisions).toEqual([2, 3]);
  expect((await s.row()).leaseRevision).toBe(3);
});

it("T8 (C2): pool, membership, renewal, warm reconnect, access and sweep writers interleave without deadlock", async () => {
  for (let round = 0; round < 4; round++) {
    const s = await readySandbox();
    const outcomes = await Promise.all([
      settle(
        updatePool(s.f.owner, {
          id: s.f.pool.id,
          slug: s.f.pool.slug,
          label: s.f.pool.label,
          maxLeaseMs: H2,
        }),
      ),
      settle(
        updatePoolMember(s.f.owner, {
          poolId: s.f.pool.id,
          sandboxHostId: s.f.host.id,
          maxLeaseMs: H1,
        }),
      ),
      settle(
        updatePoolMember(s.f.owner, {
          poolId: s.f.pool.id,
          sandboxHostId: s.f.other.id,
          maxLeaseMs: H1,
        }),
      ),
      settle(
        setSandboxTimeout(
          s.f.owner,
          { id: s.id, idempotencyKey: randomUUID(), timeoutMs: H1 },
          s.clock,
        ),
      ),
      settle(
        reconnectSandbox(
          s.f.owner,
          { id: s.id, idempotencyKey: randomUUID(), mode: "warm", timeoutMs: H1 },
          s.clock,
        ),
      ),
      settle(db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, s.id, s.clock))),
      settle(scanLeasePolicy(s.clock)),
      settle(pullInSandboxLease(s.id, s.clock)),
    ]);
    for (const outcome of outcomes) {
      if (outcome.ok) continue;
      const text = `${(outcome.error as { code?: string })?.code ?? ""} ${String(outcome.error)}`;
      expect(text).not.toMatch(/deadlock|40P01|P2034/i);
    }
    // Policy writes always land: they never lose to a reader.
    expect(outcomes[0]).toMatchObject({ ok: true });
  }
});

it("T9: an unlimited sandbox never expires by lease, yet kill, lowering and access grace still stop it", async () => {
  settings.max = null;
  const f = await poolFixture(db);
  owners.push(f.id);
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMaxLeaseMs: null },
  });
  const created = await createSandbox(f.owner, { ...f.input, timeoutMs: 0 });
  // READY with the host's acknowledgement of the unlimited lease.
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: {
      state: "READY",
      leaseRevisionEffective: 1,
      leaseExpiresAtEffective: new Date(UNLIMITED_END),
      leaseExpireActionEffective: "DESTROY",
    },
  });
  const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  expect((await row()).leaseExpiresAt?.toISOString()).toBe(UNLIMITED_END);
  // The expiry reclaim never selects it, even in the year 9000.
  await reclaimExpiredSandboxLeases(() => new Date("9000-01-01T00:00:00Z"));
  expect((await row()).state).toBe("READY");
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: created.id, idempotencyKey: { startsWith: "lease-expire:" } },
    }),
  ).toBe(0);
  // An unlimited path is never pulled in.
  expect(await scanLeasePolicy()).toBe(0);
  // Lowering the pool takes unlimited away: the sandbox is pulled in.
  await updatePool(f.owner, {
    id: f.pool.id,
    slug: f.pool.slug,
    label: f.pool.label,
    maxLeaseMs: H2,
  });
  expect(await pullInSandboxLease(created.id)).toBe(true);
  expect((await row()).leaseExpiresAt!.getTime()).toBeLessThanOrEqual(Date.now() + H2);
  // Owner kill still works on it.
  await killSandbox(f.owner, { id: created.id, idempotencyKey: randomUUID() });
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: created.id, kind: "KILL_SANDBOX" },
    }),
  ).toBe(1);
});

it("T9: access grace ends a foreign unlimited sandbox", async () => {
  const f = await poolFixture(db);
  owners.push(f.id);
  const creator = randomUUID();
  await db.inspect.user.create({
    data: { id: creator, name: "Creator", email: `${creator}@example.test` },
  });
  owners.push(creator);
  const share = await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: creator },
  });
  const member = await db.inspect.sandboxPoolMember.findUniqueOrThrow({
    where: { poolId_sandboxHostId: { poolId: f.pool.id, sandboxHostId: f.host.id } },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: creator,
      slug: randomUUID(),
      label: "Private",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: creator,
      hostOwnerId: f.id,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      templateId: revision.id,
      usagePoolId: f.pool.id,
      usageMemberId: member.id,
      state: "STOPPED",
      liveResourcesHeld: false,
      leaseExpiresAt: new Date(UNLIMITED_END),
      leaseExpireAction: "STOP",
    },
  });
  await db.inspect.share.delete({ where: { id: share.id } });
  const now = new Date("2030-01-01T00:00:00.000Z");
  await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, sandbox.id, () => now));
  const pinned = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
  expect(pinned.accessGraceUntil).not.toBeNull();
  await db.prisma.$transaction((tx) =>
    reconcileSandboxAccess(tx, sandbox.id, () => pinned.accessGraceUntil!),
  );
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
    }),
  ).toBe(1);
});

it("T11 (M4): the outbox dispatches a lease-policy renewal as a system operation; prepared input and a refusal before the frame keep it authorized", async () => {
  const s = await readySandbox();
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H2 } });
  expect(await scanLeasePolicy(s.clock)).toBe(1);
  const [renewal] = await s.ops("RENEW_SANDBOX_LEASE");
  // First attempt: refused before any frame (site: settleRefusedDispatch).
  relay.dispatchOperation.mockResolvedValueOnce("refused_before_frame");
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  await processOutbox(s.clock);
  const afterRefusal = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: renewal!.id },
  });
  expect(afterRefusal.errorCode).not.toBe("credential_inactive");
  expect(afterRefusal.state).not.toBe("FAILED");
  // Then the claim path dispatches it (site: outbox claim check).
  relay.dispatchOperation.mockClear();
  s.advance(5_000);
  for (let pass = 0; pass < 3 && relay.dispatchOperation.mock.calls.length === 0; pass++) {
    await processOutbox(s.clock);
    s.advance(5_000);
  }
  const call = relay.dispatchOperation.mock.calls
    .map((args) => (args as unknown[])[1] as Record<string, unknown>)
    .find((input) => input.operationId === renewal!.id);
  expect(call).toMatchObject({
    kind: "sandbox.lease.renew",
    authorizingPrincipal: { kind: "system" },
    lease: { revision: renewal!.leaseRevisionAccepted },
  });
  // The session manager's prepared-input check accepts the same input.
  expect(systemDispatchAllowed("sandbox.lease.renew", call!, true)).toBe(true);
  expect(systemDispatchAllowed("sandbox.lease.renew", { ...call!, envs: {} }, true)).toBe(false);
});

it("review #1: a pull-in never extends the host's acknowledged lease, even under an unacknowledged extension whose key was revoked", async () => {
  const s = await readySandbox(600_000);
  const acknowledged = (await s.row()).leaseExpiresAtEffective!;
  const key = await allOwnedPoolKey(s.f);
  // The key requests a 6h extension; the host has not acknowledged it.
  await setSandboxTimeout(
    key.principal,
    { id: s.id, idempotencyKey: randomUUID(), timeoutMs: 21_600_000 },
    s.clock,
  );
  expect((await s.row()).leaseExpiresAt!.getTime()).toBe(s.nowMs() + 21_600_000);
  await revokeSdkKey(s.f.owner, { id: key.key.id });
  // The pool limit drops to 1h: the extension now violates policy.
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H1 } });
  expect(await scanLeasePolicy(s.clock)).toBe(1);
  const system = (await s.ops("RENEW_SANDBOX_LEASE")).filter((o) =>
    o.idempotencyKey.startsWith("lease-policy:"),
  );
  expect(system).toHaveLength(1);
  // Pinned at the acknowledged deadline (10 min), never the 1h limit: the
  // system path supersedes the pending extension instead of carrying it.
  expect(system[0]!.leaseExpiresAtAccepted).toEqual(acknowledged);
  expect(system[0]!.authorizingKeyId).toBeNull();
  const row = await s.row();
  expect(row.leaseExpiresAt).toEqual(acknowledged);
  // Nothing further: what the host enforces is within the limit and nothing pends above it.
  expect(await scanLeasePolicy(s.clock)).toBe(0);
  // Every lease the system path ever sends is at or before the acknowledged one.
  for (const op of system)
    expect(op.leaseExpiresAtAccepted!.getTime()).toBeLessThanOrEqual(acknowledged.getTime());
});

it("review #1: without an acknowledged lease the pull-in waits instead of guessing", async () => {
  const s = await readySandbox();
  await db.inspect.sandbox.update({
    where: { id: s.id },
    data: {
      leaseRevisionEffective: null,
      leaseExpiresAtEffective: null,
      leaseExpireActionEffective: null,
    },
  });
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H2 } });
  expect(await scanLeasePolicy(s.clock)).toBe(0);
});

it("review round 2 #1: the system renewal is shorten-only on the wire; a host that clamped it to an earlier installed lease is adopted, never a later one", async () => {
  const s = await readySandbox();
  // The host installed the user's 10-minute shortening; its ACK is delayed,
  // so the server still believes 20h.
  await setSandboxTimeout(
    s.f.owner,
    { id: s.id, idempotencyKey: randomUUID(), timeoutMs: 600_000 },
    s.clock,
  );
  const installed = s.nowMs() + 600_000;
  // A newer 6h extension then overwrites the requested deadline.
  await setSandboxTimeout(
    s.f.owner,
    { id: s.id, idempotencyKey: randomUUID(), timeoutMs: 21_600_000 },
    s.clock,
  );
  await db.inspect.sandboxPool.update({ where: { id: s.f.pool.id }, data: { maxLeaseMs: H1 } });
  expect(await scanLeasePolicy(s.clock)).toBe(1);
  const [system] = (await s.ops("RENEW_SANDBOX_LEASE")).filter((o) =>
    o.idempotencyKey.startsWith("lease-policy:"),
  );
  const event = await eventFor(system!.id);
  // Later than what the host holds (10 min) by the server's lagging view:
  // only the host-side shorten-only rule keeps it from being an extension.
  expect(event.lease).toMatchObject({ shortenOnly: true, revision: 4 });
  expect(event.lease.deadlineUnixMs).toBeGreaterThan(installed);
  // User renewals never carry the flag.
  const user = (await s.ops("RENEW_SANDBOX_LEASE")).filter(
    (o) => !o.idempotencyKey.startsWith("lease-policy:"),
  );
  for (const op of user) expect((await eventFor(op.id)).lease).not.toHaveProperty("shortenOnly");
  // The host's census reports the clamped record (revision 4, the installed
  // 10-minute deadline). It is consistent, not a mismatch, and only ever
  // moves the server's view earlier.
  await db.inspect.sandboxOperation.update({
    where: { id: system!.id },
    data: {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: s.f.host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  const sender = { userId: s.f.id, hostId: (await s.row()).sandboxHostId!, connectionEpoch: 1 };
  const outcome = await convergeInventoryEntry(
    sender,
    {
      sandboxOwnerId: s.f.id,
      root: null,
      sandboxId: s.id,
      state: "ready",
      lease: {
        generation: 1,
        lease: {
          revision: 4,
          deadlineUnixMs: installed,
          action: event.lease.action,
          expiryPolicy: "retry-force-60s",
          shortenOnly: true,
        },
        expired: false,
        expiryComplete: false,
        timerExpired: false,
      },
    } as never,
    s.clock,
  );
  expect(outcome).not.toHaveProperty("conflict");
  const after = await s.row();
  if (after.leaseRevisionEffective === 4)
    expect(after.leaseExpiresAtEffective!.getTime()).toBe(installed);
  // Never a later effective deadline than the host holds.
  expect(after.leaseExpiresAtEffective!.getTime()).toBeLessThanOrEqual(s.nowMs() + H20);
});
