/**
 * Default-open egress relay gates on real PostgreSQL (see
 * docs/guide/network.md#refusal-reasons):
 * - `host.egress-state`: epoch, sequence and guard instance/generation
 *   fences, a server-clock 15 s lease, hello and disconnect clear it;
 * - lease expiry with no further message refuses `createEgressAdmissible`;
 * - the create-only consent/guard gate on the dispatch path and on the
 *   re-claim path (`intentReclaimGates`), terminal with the typed reason;
 * - M7: a reconnect is never refused by the server for consent or guard
 *   reasons, on either path, and carries the stored policy verbatim (no
 *   widening, no narrowing).
 */
import {
  acknowledgeFixtureExecutionConfigs,
  seedLaunchHost,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
// No sockets: relay "sends" succeed; every durable transition is real SQL.
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockReturnValue("sent"),
  },
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

const db = await pgTestDatabase();
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const { createSandbox, reconnectSandbox } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { poolFixture } = await import("../../../../packages/api/src/sandbox/testing/pool-fixtures");
const { commitHostHello } = await import("./host-hello.js");
const { recordHostEgressState } = await import("./host-egress-state.js");
const { disconnectJournalKey } = await import("./journal-key-ack.js");
const { createEgressAdmissible, intentReclaimGates } = await import("./dispatch-gates.js");
const { applyOperationResult } = await import("./operation-handlers.js");
const { lockCurrentHostEpoch } = await import("@wssp/api/sandbox/relay-fence");
const { processSandboxOutboxBatch: processOutbox } = await import("./outbox-processor.js");
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");

async function processSandboxOutboxBatch() {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  // The shared helper only acknowledges own-host configs; the foreign-node
  // fixture's host acknowledged its config on its current epoch too.
  for (const config of await db.inspect.sandboxExecutionConfig.findMany({
    where: { acknowledgedEpoch: null },
    select: { id: true, hostId: true },
    take: 100,
  })) {
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({
      where: { id: config.hostId },
      select: { connectionEpoch: true },
    });
    await db.inspect.sandboxExecutionConfig.update({
      where: { id: config.id },
      data: { acknowledgedEpoch: host.connectionEpoch, acknowledgedAt: new Date() },
    });
  }
  return processOutbox(() => new Date());
}
const dbNow = async () =>
  (await db.inspect.$queryRaw<{ now: Date }[]>`SELECT now() AS now`)[0]!.now;
const hostRow = (id: string) => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id } });

afterAll(() => db.close());
beforeEach(() => vi.clearAllMocks());

async function ownHost(epoch = 3) {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test`, twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: epoch,
      egressEnforcement: true,
    },
  });
  return { ownerId, hostId: host.id };
}

const state = (
  sequence: number,
  extra: Partial<{
    connectionEpoch: number;
    allowOpenForOthers: boolean;
    guardOk: boolean;
    guardReason: string;
    guardInstanceId: string;
    guardGeneration: number;
  }> = {},
) => {
  const guardOk = extra.guardOk ?? true;
  return {
    type: "host.egress-state" as const,
    connectionEpoch: 3,
    sequence,
    allowOpenForOthers: false,
    allowGuestSudoForOthers: false,
    guardOk,
    ...(guardOk
      ? { guardInstanceId: "guard-a", guardGeneration: 5 }
      : { guardReason: "guard_not_ok" }),
    ...extra,
  };
};

describe("host.egress-state (lease, fences)", () => {
  it("a healthy report grants a server-clock 15 s lease bound to the epoch; unhealthy clears it", async () => {
    const { ownerId, hostId } = await ownHost();
    await db.inspect.sandboxHost.update({
      where: { id: hostId },
      data: { daemonEgressGuardOk: false, daemonEgressGuardLeaseUntil: null },
    });
    const session = {
      identity: { hostId, userId: ownerId },
      connectionEpoch: 3,
      egressSequence: 0,
    };
    const before = await dbNow();
    expect(
      await recordHostEgressState(session, state(1, { allowOpenForOthers: true }), () => true),
    ).toBe(true);
    const after = await dbNow();
    const leased = await hostRow(hostId);
    expect(leased).toMatchObject({
      daemonEgressGuardOk: true,
      daemonEgressGuardEpoch: 3,
      daemonEgressGuardReason: null,
      daemonOpenEgressForOthers: true,
      daemonEgressGuardInstanceId: "guard-a",
      daemonEgressGuardGeneration: 5n,
      daemonEgressStateSequence: 1n,
    });
    const until = leased.daemonEgressGuardLeaseUntil!.getTime();
    expect(until).toBeGreaterThanOrEqual(before.getTime() + 15_000);
    expect(until).toBeLessThanOrEqual(after.getTime() + 15_000);

    expect(
      await recordHostEgressState(
        session,
        state(2, { guardOk: false, guardReason: "guard_quarantined" }),
        () => true,
      ),
    ).toBe(true);
    expect(await hostRow(hostId)).toMatchObject({
      daemonEgressGuardOk: false,
      daemonEgressGuardReason: "guard_quarantined",
      daemonEgressGuardLeaseUntil: null,
      daemonOpenEgressForOthers: false,
      // An unhealthy report without identity keeps the stored fence.
      daemonEgressGuardInstanceId: "guard-a",
    });
  });

  it("fences: stale sequence, foreign epoch, replaced link, older generation of the same instance", async () => {
    const { ownerId, hostId } = await ownHost();
    const session = {
      identity: { hostId, userId: ownerId },
      connectionEpoch: 3,
      egressSequence: 0,
    };
    expect(await recordHostEgressState(session, state(2), () => true)).toBe(true);
    const leased = (await hostRow(hostId)).daemonEgressGuardLeaseUntil;
    const unhealthy = { guardOk: false, guardReason: "guard_not_ok" };
    expect(await recordHostEgressState(session, state(2, unhealthy), () => true)).toBe(false);
    expect(await recordHostEgressState(session, state(1, unhealthy), () => true)).toBe(false);
    expect(
      await recordHostEgressState(
        session,
        state(3, { ...unhealthy, connectionEpoch: 4 }),
        () => true,
      ),
    ).toBe(false);
    expect(await recordHostEgressState(session, state(4, unhealthy), () => false)).toBe(false);
    // An older generation of the same guard instance is ignored ...
    expect(await recordHostEgressState(session, state(5, { guardGeneration: 4 }), () => true)).toBe(
      false,
    );
    expect((await hostRow(hostId)).daemonEgressGuardLeaseUntil).toEqual(leased);
    // ... the same or a newer one renews; a new instance resets the fence.
    expect(await recordHostEgressState(session, state(6), () => true)).toBe(true);
    expect(
      await recordHostEgressState(
        session,
        state(7, { guardInstanceId: "guard-b", guardGeneration: 1 }),
        () => true,
      ),
    ).toBe(true);
    expect(await hostRow(hostId)).toMatchObject({
      daemonEgressGuardInstanceId: "guard-b",
      daemonEgressGuardGeneration: 1n,
      daemonEgressGuardOk: true,
    });
    // A newer hello committed: the row's epoch no longer matches the session.
    await db.inspect.sandboxHost.update({ where: { id: hostId }, data: { connectionEpoch: 4 } });
    expect(await recordHostEgressState(session, state(8, unhealthy), () => true)).toBe(false);
    expect((await hostRow(hostId)).daemonEgressGuardOk).toBe(true);
  });

  it("hello resets consent and the lease (schedulable only after a report); disconnect nulls the lease", async () => {
    const { ownerId, hostId } = await ownHost(1);
    await db.inspect.sandboxHost.update({
      where: { id: hostId },
      data: { daemonOpenEgressForOthers: true },
    });
    const epoch = await commitHostHello({
      identity: { hostId, userId: ownerId },
      now: new Date(),
      message: (() => {
        const message = helloFixture(hostId, false);
        (message.daemon.capabilities as Record<string, unknown>).egress = {
          open: true,
          guard: true,
        };
        return message;
      })(),
    });
    expect(await hostRow(hostId)).toMatchObject({
      connectionEpoch: epoch,
      daemonEgressGuardEpoch: epoch,
      daemonEgressGuardOk: true,
      daemonEgressGuardLeaseUntil: null,
      daemonOpenEgressForOthers: false,
      daemonEgressStateSequence: null,
    });
    const session = {
      identity: { hostId, userId: ownerId },
      connectionEpoch: epoch,
      egressSequence: 0,
    };
    expect(
      await recordHostEgressState(session, { ...state(1), connectionEpoch: epoch }, () => true),
    ).toBe(true);
    expect((await hostRow(hostId)).daemonEgressGuardLeaseUntil).not.toBeNull();
    await disconnectJournalKey(
      { hostId, userId: ownerId, connectionEpoch: epoch },
      new Date(),
      false,
    );
    expect((await hostRow(hostId)).daemonEgressGuardLeaseUntil).toBeNull();
  });

  it("lease expiry: a last healthy report 16 s old is refused by createEgressAdmissible with no further message", async () => {
    const { ownerId, hostId } = await ownHost();
    const now = await dbNow();
    await db.inspect.sandboxHost.update({
      where: { id: hostId },
      data: { daemonEgressGuardLeaseUntil: new Date(now.getTime() - 1_000) },
    });
    const gate = (at: Date) =>
      db.inspect.$transaction((tx) =>
        createEgressAdmissible(tx, {
          hostId,
          hostOwnerId: ownerId,
          sandboxOwnerId: ownerId,
          policy: { domains: [], cidrs: [] },
          now: at,
        }),
      );
    expect(await gate(now)).toBe("egress_guard_unavailable");
    expect(await gate(new Date(now.getTime() - 2_000))).toBeNull();
  });
});

/** A direct own-host create (allowlist), pending in the outbox. */
async function ownCreate() {
  const { ownerId, hostId } = await ownHost(1);
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: hostId,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: `sha256:${"d".repeat(64)}`,
    },
  });
  const sandbox = await createSandbox(
    { kind: "session", ownerId },
    createSandboxInput.parse({
      template: `revision/${template.id}`,
      sandboxHostId: hostId,
      idempotencyKey: `create-${randomUUID()}`,
      egress: { domains: ["example.com"] },
    }),
  );
  return { ownerId, hostId, sandboxId: sandbox.id };
}

/** A use grantee's pool create placed OPEN on the pool owner's (foreign) host. */
async function foreignOpenCreate() {
  const f = await poolFixture(db);
  const id = randomUUID();
  await db.inspect.user.create({
    data: { id, name: "Grantee", email: `${id}@example.test`, twoFactorEnabled: true },
  });
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: id },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: f.host.id,
      slug: "g",
      label: "Grantee",
      incusFingerprint: f.revision.incusFingerprint,
    },
  });
  await db.inspect.sandboxPoolMember.updateMany({
    where: { sandboxHostId: f.other.id },
    data: { enabled: false },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      daemonFeatures: { egressPolicy: true, terminal: true, egressOpen: true },
      daemonOpenEgressForOthers: true,
    },
  });
  const sandbox = await createSandbox(
    { kind: "session", ownerId: id },
    createSandboxInput.parse({
      poolId: f.pool.id,
      template: `revision/${revision.id}`,
      idempotencyKey: randomUUID(),
    }),
  );
  const stored = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
  expect(stored).toMatchObject({
    sandboxHostId: f.host.id,
    egressPolicy: { mode: "open", domains: [], cidrs: [] },
  });
  return { ownerId: id, hostId: f.host.id, hostOwnerId: f.id, sandboxId: sandbox.id, stored };
}

async function op(sandboxId: string, kind: "CREATE_SANDBOX" | "RECONNECT_SANDBOX") {
  return db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId, kind },
    orderBy: { createdAt: "desc" },
  });
}
async function eventFor(sandboxId: string, operationId: string) {
  return db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandboxId, payload: { path: ["operationId"], equals: operationId } },
  });
}
async function reclaimVerdict(
  f: { ownerId: string; hostId: string; hostOwnerId?: string; sandboxId: string },
  operationId: string,
  kind: "sandbox.create" | "sandbox.reconnect",
) {
  const event = await eventFor(f.sandboxId, operationId);
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } });
  return db.inspect.$transaction(async (tx) => {
    // The re-claim callers hold H at the current epoch.
    await lockCurrentHostEpoch(tx, f.hostId);
    return intentReclaimGates(tx, {
      ownerId: f.ownerId,
      hostId: f.hostId,
      hostOwnerId: f.hostOwnerId ?? f.ownerId,
      kind,
      payload: event.payload as Record<string, unknown>,
      operationAuthorizingKeyId: null,
      sandbox,
      now: await dbNow(),
      restore: false,
    });
  });
}
const expireLease = (hostId: string) =>
  db.inspect.sandboxHost.update({
    where: { id: hostId },
    data: { daemonEgressGuardLeaseUntil: new Date(0) },
  });

describe("createEgressAdmissible: creates only, both paths (M7)", () => {
  it("guard lapses between placement and dispatch: the create fails with egress_guard_unavailable, zero sends; re-claim refuses", async () => {
    const f = await ownCreate();
    const create = await op(f.sandboxId, "CREATE_SANDBOX");
    expect(await reclaimVerdict(f, create.id, "sandbox.create")).toBe("active");
    await expireLease(f.hostId);
    expect(await reclaimVerdict(f, create.id, "sandbox.create")).toBe("refused");
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(await op(f.sandboxId, "CREATE_SANDBOX")).toMatchObject({
      state: "FAILED",
      errorCode: "egress_guard_unavailable",
    });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({ lastErrorCode: "egress_guard_unavailable" });
  });

  it("consent revoked between placement and dispatch: the open create fails with open_egress_not_permitted (never narrowed)", async () => {
    const f = await foreignOpenCreate();
    const create = await op(f.sandboxId, "CREATE_SANDBOX");
    expect(await reclaimVerdict(f, create.id, "sandbox.create")).toBe("active");
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { daemonOpenEgressForOthers: false },
    });
    expect(await reclaimVerdict(f, create.id, "sandbox.create")).toBe("refused");
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(await op(f.sandboxId, "CREATE_SANDBOX")).toMatchObject({
      state: "FAILED",
      errorCode: "open_egress_not_permitted",
    });
    // The stored effective policy is not rewritten.
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } })).egressPolicy,
    ).toEqual({ mode: "open", domains: [], cidrs: [] });
  });

  it("a RUNNING foreign open sandbox reconnects with consent revoked AND the guard down, on both paths, policy verbatim", async () => {
    const f = await foreignOpenCreate();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    const create = await op(f.sandboxId, "CREATE_SANDBOX");
    const createEvent = await eventFor(f.sandboxId, create.id);
    expect(
      await applyOperationResult({
        sender: { userId: f.hostOwnerId, hostId: f.hostId, connectionEpoch: 1 },
        operationId: create.id,
        sandboxId: f.sandboxId,
        generation: create.generation,
        attempt: 1,
        state: "succeeded",
        result: { state: "ready", lease: (createEvent.payload as Record<string, unknown>).lease },
      }),
    ).toMatchObject({ written: true });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } })).state).toBe(
      "READY",
    );

    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: {
        daemonOpenEgressForOthers: false,
        daemonEgressGuardOk: false,
        daemonEgressGuardLeaseUntil: null,
      },
    });
    await reconnectSandbox(
      { kind: "session", ownerId: f.ownerId },
      { id: f.sandboxId, idempotencyKey: randomUUID(), mode: "warm" },
    );
    const reconnect = await op(f.sandboxId, "RECONNECT_SANDBOX");
    // (b) re-claim: the server gate admits the reconnect.
    expect(await reclaimVerdict(f, reconnect.id, "sandbox.reconnect")).toBe("active");
    // (a) dispatch: sent, carrying the stored policy and hash unchanged.
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    const [, message] = vi.mocked(manager.dispatchOperation).mock.calls[0]!;
    expect(message).toMatchObject({
      kind: "sandbox.reconnect",
      egressPolicy: { mode: "open", domains: [], cidrs: [] },
      egressPolicyHash: f.stored.egressPolicyHash,
    });
    expect(await op(f.sandboxId, "RECONNECT_SANDBOX")).not.toMatchObject({ state: "FAILED" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({
      egressPolicy: f.stored.egressPolicy,
      egressPolicyHash: f.stored.egressPolicyHash,
    });
  });

  it("a STOPPED sandbox's reconnect re-claim verdict never depends on consent or the guard (the daemon refuses the cold start)", async () => {
    const f = await foreignOpenCreate();
    const create = await op(f.sandboxId, "CREATE_SANDBOX");
    await db.inspect.sandbox.update({ where: { id: f.sandboxId }, data: { state: "STOPPED" } });
    const healthy = await reclaimVerdict(f, create.id, "sandbox.reconnect");
    expect(healthy).toBe("active");
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: {
        daemonOpenEgressForOthers: false,
        daemonEgressGuardOk: false,
        daemonEgressGuardLeaseUntil: null,
      },
    });
    expect(await reclaimVerdict(f, create.id, "sandbox.reconnect")).toBe(healthy);
  });
});
