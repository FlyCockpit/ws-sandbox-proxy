/**
 * Default-open egress on real PostgreSQL (see docs/guide/network.md#other-users-hosts):
 * the effective policy is resolved once at materialization
 * (own → open, foreign without consent → allowlist NODE_POLICY, no open
 * capability → HOST_UNSUPPORTED), the guard lease is a hard filter in both
 * modes for direct placement, pool placement and queue admission (an expired
 * lease refuses with no further message), consent only ranks, and a queued
 * create materializes on its host when placed.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "egress-placement-fixture",
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
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { runCapacityQueuePass } from "./capacity-queue";
import { leaseNow } from "./lease";
import { createSandbox } from "./services/sandboxes";
import { poolFixture } from "./testing/pool-fixtures";
import { seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

type Fixture = Awaited<ReturnType<typeof poolFixture>>;
const GUARD_REFUSAL = {
  data: { code: "UNSUPPORTED_CAPABILITY", reason: "egress_guard_unavailable" },
};

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
  await db.inspect.share.create({
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
  return {
    id,
    owner: { kind: "session" as const, ownerId: id },
    input: (extra: Record<string, unknown> = {}) => ({
      poolId: f.pool.id,
      template: `revision/${revision.id}`,
      idempotencyKey: randomUUID(),
      ...extra,
    }),
  };
}

/** Static open capability and live consent on a fixture host. */
async function setEgress(hostId: string, egressOpen: boolean, consent = false) {
  await db.inspect.sandboxHost.update({
    where: { id: hostId },
    data: {
      daemonFeatures: { egressPolicy: true, terminal: true, egressOpen },
      daemonOpenEgressForOthers: consent,
    },
  });
}
const row = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
const direct = (f: Fixture, extra: Record<string, unknown> = {}) => ({
  template: "base",
  sandboxHostId: f.host.id,
  idempotencyKey: randomUUID(),
  ...extra,
});

describe("resolveEffectiveEgress at materialization", () => {
  it("own capable host → open; the request is stored and the outbox carries the effective policy", async () => {
    const f = await poolFixture(db);
    await setEgress(f.host.id, true);
    const created = await createSandbox(f.owner, direct(f));
    const stored = await row(created.id);
    expect(stored).toMatchObject({
      egressPolicy: { mode: "open", domains: [], cidrs: [] },
      egressRequest: { mode: "open", domains: [], cidrs: [] },
      egressModeReason: null,
    });
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: created.id },
    });
    expect(event.payload).toMatchObject({
      egressPolicy: { mode: "open", domains: [], cidrs: [] },
      egressPolicyHash: stored.egressPolicyHash,
    });
  });

  it("guard ok but no open capability → allowlist with the fallback grants, HOST_UNSUPPORTED", async () => {
    const f = await poolFixture(db);
    await setEgress(f.host.id, false);
    const created = await createSandbox(
      f.owner,
      direct(f, { egress: { mode: "open", domains: ["pypi.org"] } }),
    );
    expect(await row(created.id)).toMatchObject({
      egressPolicy: { domains: ["pypi.org"], cidrs: [] },
      egressRequest: { mode: "open", domains: ["pypi.org"], cidrs: [] },
      egressModeReason: "HOST_UNSUPPORTED",
    });
  });

  it("an allowlist request stays allowlist on a capable own host", async () => {
    const f = await poolFixture(db);
    await setEgress(f.host.id, true);
    const created = await createSandbox(f.owner, direct(f, { egress: { domains: [], cidrs: [] } }));
    expect(await row(created.id)).toMatchObject({
      egressPolicy: { domains: [], cidrs: [] },
      egressModeReason: null,
      egressPolicyHash: "cd54f076503987212abf92b598f837d67f1e70de63317600961cf181ef0f7caa",
    });
  });

  it("foreign node: allowlist with NODE_POLICY without consent, open with consent; consent never filters", async () => {
    const f = await poolFixture(db);
    const g = await grantee(f);
    for (const host of f.hosts) await setEgress(host.id, true, false);
    const denied = await createSandbox(g.owner, g.input({ egress: { domains: ["pypi.org"] } }));
    // An explicit domains key without mode is an allowlist request.
    expect((await row(denied.id)).egressModeReason).toBeNull();
    const fallback = await createSandbox(
      g.owner,
      g.input({ egress: { mode: "open", domains: ["pypi.org"] } }),
    );
    expect(await row(fallback.id)).toMatchObject({
      egressPolicy: { domains: ["pypi.org"], cidrs: [] },
      egressModeReason: "NODE_POLICY",
    });
    await setEgress(f.other.id, true, true);
    // Ranking prefers the consenting foreign host for an open request.
    const open = await createSandbox(g.owner, g.input());
    expect(await row(open.id)).toMatchObject({
      sandboxHostId: f.other.id,
      egressPolicy: { mode: "open", domains: [], cidrs: [] },
      egressModeReason: null,
    });
  });
});

describe("guard lease hard filter (M11, M18), both modes", () => {
  it("an old daemon (no guard report) is never a candidate: direct refuses, pool refuses without a WAITING row", async () => {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: {
        daemonEgressGuardOk: false,
        daemonEgressGuardEpoch: null,
        daemonEgressGuardLeaseUntil: null,
      },
    });
    for (const egress of [undefined, { mode: "allowlist" }])
      await expect(
        createSandbox(f.owner, direct(f, egress ? { egress } : {})),
      ).rejects.toMatchObject(GUARD_REFUSAL);
    await expect(
      createSandbox(f.owner, {
        ...f.input,
        idempotencyKey: randomUUID(),
        waitForCapacityMs: 3_600_000,
      }),
    ).rejects.toMatchObject(GUARD_REFUSAL);
    await expect(
      createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject(GUARD_REFUSAL);
    expect(await db.inspect.sandboxCapacityWait.count({ where: { poolId: f.pool.id } })).toBe(0);
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  });

  it("a guard bit from an older epoch is ignored", async () => {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { daemonEgressGuardEpoch: 0 },
    });
    await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject(GUARD_REFUSAL);
  });

  it("lease expiry: a last healthy report 16 s old refuses direct, pool and queue admission with no further message", async () => {
    const f = await poolFixture(db);
    // Leased at T: until T + 15 s. Observed at T + 16 s (server clock).
    const [{ now }] = await db.inspect.$queryRaw<{ now: Date }[]>`SELECT now() AS now`;
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { daemonEgressGuardLeaseUntil: new Date(now.getTime() - 1_000) },
    });
    await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject(GUARD_REFUSAL);
    await expect(
      createSandbox(f.owner, {
        ...f.input,
        idempotencyKey: randomUUID(),
        waitForCapacityMs: 3_600_000,
      }),
    ).rejects.toMatchObject(GUARD_REFUSAL);
    expect(await db.inspect.sandboxCapacityWait.count({ where: { poolId: f.pool.id } })).toBe(0);
    // One member renews: the pool places there.
    await db.inspect.sandboxHost.update({
      where: { id: f.other.id },
      data: { daemonEgressGuardLeaseUntil: new Date(now.getTime() + 60_000) },
    });
    const placed = await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    expect(placed.sandboxHostId).toBe(f.other.id);
  });
});

describe("queued creates", () => {
  it("a waiting open create materializes on a foreign host as NODE_POLICY allowlist; a guard lapse keeps it waiting", async () => {
    const f = await poolFixture(db);
    const g = await grantee(f);
    for (const host of f.hosts) await setEgress(host.id, true, false);
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { memoryReservedMiB: 65536 },
    });
    const waiting = await createSandbox(
      g.owner,
      g.input({ waitForCapacityMs: 3_600_000, egress: { mode: "open", domains: ["pypi.org"] } }),
    );
    expect(waiting.state).toBe("WAITING_FOR_CAPACITY");
    expect(await row(waiting.id)).toMatchObject({
      egressPolicy: null,
      egressPolicyHash: null,
      egressRequest: { mode: "open", domains: ["pypi.org"], cidrs: [] },
      egressModeReason: null,
    });
    // Capacity frees while every guard lease lapsed: the entry keeps waiting.
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { memoryReservedMiB: 0, daemonEgressGuardLeaseUntil: new Date(0) },
    });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect((await row(waiting.id)).state).toBe("WAITING_FOR_CAPACITY");
    expect(
      (await db.inspect.sandboxCapacityWait.findUniqueOrThrow({ where: { sandboxId: waiting.id } }))
        .state,
    ).toBe("WAITING");
    // The guard renews: the queue places it, resolving the effective policy now.
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data: { daemonEgressGuardLeaseUntil: new Date("2999-01-01T00:00:00.000Z") },
    });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    expect(await row(waiting.id)).toMatchObject({
      state: "REQUESTED",
      egressPolicy: { domains: ["pypi.org"], cidrs: [] },
      egressRequest: { mode: "open", domains: ["pypi.org"], cidrs: [] },
      egressModeReason: "NODE_POLICY",
    });
  });
});
