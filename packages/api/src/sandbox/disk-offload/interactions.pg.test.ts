import { digestContextSnapshot } from "../digest-context";
import { requestDigestMetadata } from "../idempotency";

/**
 * Offload interactions on real PostgreSQL: destroy during upload (the kill supersedes
 * the live offload), destroy of an OFFLOADED sandbox (stale copies re-asked
 * for discard; a waiting restore cancelled), owner deletion cascading the
 * ended offload, Forget unreachable host (refused while possibly live,
 * allowed through the safe-detachment gate, never DELETED, other disks keep
 * blocking), drain `--offload`, access loss on a foreign host (SYSTEM_DETACH),
 * the capture refusal, and the lease reaper's exclusion of OFFLOADED.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "interactions-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("../budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("../sharing-budgets", () => ({
  consumePoolCapacityRead: async () => {},
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeLeasePreview: async () => {},
  consumeInviteIssue: async () => {},
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Principal } from "../contracts";

const db = await pgTestDatabase();
afterAll(() => db.close());

const { seedOwner } = await import("../../webhooks/testing/fixtures");
const { sessionPrincipal } = await import("../index");
const { createSandbox, killSandbox, reconnectSandbox } = await import("../services/sandboxes");
const { forgetHost, setHostDraining } = await import("../services/hosts");
const { captureSandbox } = await import("../image-store/captures");
const {
  OFFLOAD_HOST_FEATURES,
  offloadSandboxForTest,
  seedOpenDiskSession,
  seedStoppedOnHost,
  seedStoredOffload,
} = await import("../testing/offload-fixtures");
const { seedSandboxInstance } = await import("../testing/resource-fixtures");
const { poolFixture } = await import("../testing/pool-fixtures");
const { detachToOffloaded } = await import("./detach");
const { evictSuggestions } = await import("./evict");
const { lockHostByEpoch } = await import("../relay-fence");
const { lockHostForSandboxOperation } = await import("../host-admission");
const { commitLockedSandboxLeaseExpiry, leaseNow, reclaimExpiredSandboxLeases } = await import(
  "../lease"
);
const { reconcileSandboxAccess } = await import("../sharing-access");
const { deleteAccountInTransaction } = await import("@wssp/db/account-deletion");

const ENV = {
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
  IMAGE_S3_BUCKET: "b",
  IMAGE_S3_ENDPOINT: "http://127.0.0.1:9",
  IMAGE_S3_ACCESS_KEY_ID: "a",
  IMAGE_S3_SECRET_ACCESS_KEY: "s",
  SANDBOX_OFFLOAD: "auto",
};
const saved: Record<string, string | undefined> = {};
beforeAll(() => {
  for (const [key, value] of Object.entries(ENV)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
});
afterAll(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});

const HOUR = 3_600_000;
const row = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
const code = (error: unknown) => (error as { data?: { code?: string } }).data?.code;

/** A STOPPED sandbox on its own (or `hostOwner`'s) host; `stored` caches a STORED copy. */
async function world(input: { stored?: boolean; hostOwner?: string } = {}) {
  const owner = await seedOwner(db.inspect);
  const { host, revision, sandbox } = await seedStoppedOnHost(db.inspect, {
    userId: owner,
    ...(input.hostOwner ? { hostOwnerId: input.hostOwner } : {}),
  });
  let offloadId: string | null = null;
  if (input.stored !== false) {
    const stored = await seedStoredOffload(db.inspect, {
      userId: owner,
      sandboxId: sandbox.id,
      hostId: host.id,
    });
    await db.inspect.sandboxDiskOffload.update({
      where: { id: stored.offloadId },
      data: {
        sourceGeneration: sandbox.generation,
        sourceHostOwnerId: input.hostOwner ?? owner,
      },
    });
    await db.inspect.sandbox.update({
      where: { id: sandbox.id },
      data: { diskOffloadId: stored.offloadId, cachedOffloadSeq: 1, offloadSeq: 1 },
    });
    // A STORED upload's transfer completed with it.
    await db.inspect.sandboxImageTransfer.update({
      where: { id: stored.transferId },
      data: { state: "COMPLETE" },
    });
    offloadId = stored.offloadId;
  }
  const counters = async () => {
    const h = await db.inspect.sandboxHost.findUnique({ where: { id: host.id } });
    const pools = await db.inspect.sandboxHostStoragePool.findMany({
      where: { sandboxHostId: host.id },
    });
    return {
      rootCount: h?.rootCount ?? null,
      reserved: pools.reduce((n, p) => n + p.diskReservedGiB, 0),
    };
  };
  return {
    owner,
    principal: sessionPrincipal(owner),
    host,
    revision,
    sandbox,
    offloadId,
    counters,
  };
}
type World = Awaited<ReturnType<typeof world>>;

/** Detach `w.sandbox` with the given proof (as evict or census would). */
async function detach(w: World, proof: "root_absent" | "stale_copy") {
  const s = await row(w.sandbox.id);
  return db.prisma.$transaction(async (tx) => {
    await lockHostByEpoch(tx, w.host.id, w.host.connectionEpoch, w.host.userId);
    return detachToOffloaded(tx, {
      sandboxId: s.id,
      userId: s.userId,
      hostId: w.host.id,
      generation: s.generation,
      proof:
        proof === "root_absent"
          ? { kind: "root_absent" }
          : { kind: "stale_copy", createKey: "create-key-1", baseFingerprint: "sha256:base" },
    });
  });
}

/** The host went silent a day ago. */
async function unreachable(w: World) {
  const long = new Date(Date.now() - 24 * HOUR);
  await db.inspect.sandboxHost.update({
    where: { id: w.host.id },
    data: { status: "DISCONNECTED", lastHeartbeatAt: long, lastConnectedAt: long },
  });
}

describe("destroy (§8.9, §11)", () => {
  it("destroy during upload: the kill supersedes the live offload (session aborted, keys shredded)", async () => {
    const w = await world({ stored: false });
    const open = await seedOpenDiskSession(db.inspect, {
      userId: w.owner,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
    });
    await db.inspect.sandboxDiskOffload.update({
      where: { id: open.offloadId },
      data: { sourceGeneration: w.sandbox.generation },
    });
    await killSandbox(w.principal, { id: w.sandbox.id, idempotencyKey: randomUUID() });
    expect((await row(w.sandbox.id)).state).toBe("STOPPING");
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: w.sandbox.id, kind: "KILL_SANDBOX" },
    });
    // No stored disk: an ordinary destroy, never an offload intent.
    expect(kill.teardownIntent).toBeNull();
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: open.offloadId },
    });
    expect(offload).toMatchObject({ state: "SUPERSEDED", liveSandboxId: null });
    expect(offload.shreddedAt).not.toBeNull();
    expect(offload.wrappedKey).toBeNull();
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { id: open.sessionId },
    });
    expect(session.state).not.toBe("OPEN");
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: open.transferId } }),
    ).toMatchObject({ state: "CANCELLED" });
  });

  it("destroy of OFFLOADED is server-completed and re-asks its stale copies for discard", async () => {
    const w = await world();
    expect(await detach(w, "stale_copy")).toBe(true);
    await db.inspect.sandboxDiskCopy.updateMany({
      where: { sandboxId: w.sandbox.id },
      data: { discardSentAt: new Date() },
    });
    const result = await killSandbox(w.principal, {
      id: w.sandbox.id,
      idempotencyKey: randomUUID(),
    });
    expect(result).toMatchObject({ state: "DELETED" });
    expect(await row(w.sandbox.id)).toMatchObject({ state: "DELETED", diskOffloadId: null });
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: w.offloadId! } }),
    ).toMatchObject({ state: "DELETING" });
    const copies = await db.inspect.sandboxDiskCopy.findMany({
      where: { sandboxId: w.sandbox.id },
    });
    expect(copies).toHaveLength(1);
    expect(copies[0]).toMatchObject({ state: "STALE", discardSentAt: null });
    // Nothing went to the host.
    expect(
      await db.inspect.outboxEvent.count({
        where: { aggregateId: w.sandbox.id, eventType: "sandbox.kill_requested" },
      }),
    ).toBe(0);
  });

  it("destroy while a restore waits ends the wait CANCELLED and its operation cancelled", async () => {
    const f = await poolFixture(db);
    for (const host of [f.host, f.other])
      await db.inspect.sandboxHost.update({
        where: { id: host.id },
        data: {
          daemonFeatures: { ...OFFLOAD_HOST_FEATURES, egressOpen: true },
          daemonDiskOffload: true,
        },
      });
    const created = await createSandbox(f.owner, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    });
    await offloadSandboxForTest(db.inspect, {
      userId: f.id,
      sandboxId: created.id,
      hostId: f.host.id,
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: { in: [f.host.id, f.other.id] } },
      data: { newRootsAllowed: false },
    });
    const accepted = await reconnectSandbox(
      f.owner,
      { id: created.id, idempotencyKey: randomUUID(), waitForCapacityMs: 60_000 },
      leaseNow,
    );
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: accepted.operationId },
      }),
    ).toMatchObject({ state: "WAITING" });
    await killSandbox(f.owner, { id: created.id, idempotencyKey: randomUUID() });
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: accepted.operationId },
      }),
    ).toMatchObject({ state: "CANCELLED", intent: null });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }))
        .state,
    ).toBe("CANCELLED");
    expect(await row(created.id)).toMatchObject({ state: "DELETED", diskOffloadId: null });
  });

  it("owner deletion: a destroyed OFFLOADED sandbox's offload cascades with the account", async () => {
    const hostOwner = await seedOwner(db.inspect);
    const w = await world({ hostOwner });
    expect(await detach(w, "root_absent")).toBe(true);
    await killSandbox(w.principal, { id: w.sandbox.id, idempotencyKey: randomUUID() });
    expect(await row(w.sandbox.id)).toMatchObject({ state: "DELETED", diskOffloadId: null });
    await db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, w.owner));
    expect(await db.inspect.user.count({ where: { id: w.owner } })).toBe(0);
    // The DELETING row (and its wrapped key) went with the account; the disk
    // sweeper deletes the object outside the keep set.
    expect(await db.inspect.sandboxDiskOffload.count({ where: { userId: w.owner } })).toBe(0);
  });
});

describe("Forget unreachable host (§8.2 N1, CN1)", () => {
  it("refuses a connected host", async () => {
    const w = await world();
    await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: { status: "CONNECTED", lastHeartbeatAt: new Date() },
    });
    const error = await forgetHost(w.principal, { id: w.host.id }).catch((e: unknown) => e);
    expect(code(error)).toBe("sandbox.host_delete_conflict");
    expect(await row(w.sandbox.id)).toMatchObject({ state: "STOPPED" });
  });

  it("refuses sandbox.host_forget_unsafe, listing a possibly-live sandbox, and writes nothing", async () => {
    const w = await world();
    await unreachable(w);
    await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v1" }),
        ...requestDigestMetadata("STOP_SANDBOX"),

        userId: w.owner,
        sandboxId: w.sandbox.id,
        kind: "STOP_SANDBOX",
        state: "UNKNOWN_OUTCOME",
        generation: w.sandbox.generation,
        dispatchedHostId: w.host.id,
        dispatchAttempt: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "h",
      },
    });
    const before = await w.counters();
    const error = await forgetHost(w.principal, { id: w.host.id }).catch((e: unknown) => e);
    expect(code(error)).toBe("sandbox.host_forget_unsafe");
    expect((error as { data: { sandboxIds: string[] } }).data.sandboxIds).toEqual([w.sandbox.id]);
    expect(await row(w.sandbox.id)).toMatchObject({
      state: "STOPPED",
      sandboxHostId: w.host.id,
      diskOffloadId: w.offloadId,
    });
    expect(await w.counters()).toEqual(before);
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: w.host.id } });
    expect(host.deletionRequestedAt).toBeNull();
  });

  it("detaches a stored disk through the gate, drops the host's copies and deletes the host", async () => {
    const w = await world();
    await unreachable(w);
    const result = await forgetHost(w.principal, { id: w.host.id });
    expect(result).toEqual({ ok: true, pending: false, detached: 1, copiesForgotten: 1 });
    expect(await row(w.sandbox.id)).toMatchObject({
      state: "OFFLOADED",
      sandboxHostId: null,
      diskOffloadId: w.offloadId,
      diskReservationHeld: false,
    });
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: w.offloadId! } }),
    ).toMatchObject({ state: "STORED" });
    expect(await db.inspect.sandboxDiskCopy.count({ where: { sandboxId: w.sandbox.id } })).toBe(0);
    expect(await db.inspect.sandboxHost.count({ where: { id: w.host.id } })).toBe(0);
    // Never DELETED.
    expect(await db.inspect.sandbox.count({ where: { id: w.sandbox.id, state: "DELETED" } })).toBe(
      0,
    );
  });

  it("a disk with no stored copy keeps blocking: forget detaches the rest, deletion stays pending", async () => {
    const w = await world();
    await unreachable(w);
    const plain = await seedSandboxInstance(db.inspect, {
      data: {
        userId: w.owner,
        templateId: w.revision.id,
        sandboxHostId: w.host.id,
        hostOwnerId: w.owner,
        originHostId: w.host.id,
        state: "STOPPED",
      },
    });
    const result = await forgetHost(w.principal, { id: w.host.id });
    expect(result).toMatchObject({ ok: true, pending: true, detached: 1, copiesForgotten: 1 });
    expect((await row(w.sandbox.id)).state).toBe("OFFLOADED");
    expect(await row(plain.id)).toMatchObject({
      state: "STOPPED",
      sandboxHostId: w.host.id,
      diskReservationHeld: true,
    });
    expect(await w.counters()).toEqual({ rootCount: 1, reserved: plain.rootChargeGiB });
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: w.host.id } });
    expect(host.deletionRequestedAt).not.toBeNull();
  });
});

describe("drain --offload (§10 C7)", () => {
  it("a draining host with offload feeds eviction suggestions; undrain clears the switch", async () => {
    const w = await world();
    const drained = await setHostDraining(w.principal, {
      id: w.host.id,
      draining: true,
      offload: true,
    });
    expect(drained).toMatchObject({ id: w.host.id, draining: true, offload: true });
    const suggested = await evictSuggestions();
    expect(suggested.find((s) => s.hostId === w.host.id)?.frame).toMatchObject({
      type: "disk.evict.suggest",
      sandboxId: w.sandbox.id,
      offloadId: w.offloadId,
    });
    const undrained = await setHostDraining(w.principal, { id: w.host.id, draining: false });
    expect(undrained).toMatchObject({ draining: false, offload: false });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: w.host.id } })).drainOffload,
    ).toBe(false);
    expect((await evictSuggestions()).some((s) => s.hostId === w.host.id)).toBe(false);
  });

  it("a plain drain does not suggest evictions", async () => {
    const w = await world();
    await setHostDraining(w.principal, { id: w.host.id, draining: true });
    expect((await evictSuggestions()).some((s) => s.hostId === w.host.id)).toBe(false);
  });
});

describe("access, capture and the lease reaper (§10 C7)", () => {
  it("access loss on a foreign host destroys a stored-disk sandbox as SYSTEM_DETACH (T16)", async () => {
    const hostOwner = await seedOwner(db.inspect);
    const w = await world({ hostOwner });
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { accessGraceUntil: new Date(Date.now() - 60_000), accessGraceReason: "access" },
    });
    const queued = await db.prisma.$transaction(async (tx) => {
      await lockHostForSandboxOperation(tx, w.host.id, w.owner, w.sandbox.id);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${w.sandbox.id} FOR NO KEY UPDATE`;
      const s = await tx.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } });
      return commitLockedSandboxLeaseExpiry(tx, s, new Date(), false, "access");
    });
    expect(queued).toBe(true);
    const s = await row(w.sandbox.id);
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: w.sandbox.id, kind: "KILL_SANDBOX", generation: s.generation },
    });
    expect(kill.teardownIntent).toBe("SYSTEM_DETACH");
  });

  it("access reconcile leaves an OFFLOADED sandbox alone", async () => {
    const hostOwner = await seedOwner(db.inspect);
    const w = await world({ hostOwner });
    expect(await detach(w, "root_absent")).toBe(true);
    const before = await row(w.sandbox.id);
    expect(
      await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, w.sandbox.id, leaseNow)),
    ).toBe(false);
    expect(await row(w.sandbox.id)).toEqual(before);
  });

  it("capture of an OFFLOADED sandbox is refused sandbox.disk_offloaded", async () => {
    const w = await world();
    expect(await detach(w, "root_absent")).toBe(true);
    const error = await captureSandbox(w.principal as Principal, {
      id: w.sandbox.id,
      idempotencyKey: randomUUID(),
    }).catch((e: unknown) => e);
    expect(code(error)).toBe("sandbox.disk_offloaded");
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: w.sandbox.id, kind: "CAPTURE_TEMPLATE" },
      }),
    ).toBe(0);
  });

  it("the lease reaper never selects an OFFLOADED sandbox", async () => {
    const w = await world();
    expect(await detach(w, "root_absent")).toBe(true);
    const before = await row(w.sandbox.id);
    await reclaimExpiredSandboxLeases(() => new Date(Date.now() + 365 * 24 * HOUR));
    expect(await row(w.sandbox.id)).toEqual(before);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: w.sandbox.id, kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] } },
      }),
    ).toBe(0);
  });
});
