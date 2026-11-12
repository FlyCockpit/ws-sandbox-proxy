import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "../digest-context";
import { requestDigestMetadata } from "../idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * Eviction, stale copies and their accounting against real PostgreSQL
 * the evict CAS
 * (every precondition), the grant fence on `disk.evicted`, expired grants,
 * the discard arms, the reservation rebuild and host-delete blocker counting
 * copy rows, and the account-deletion blocker.
 */
const db = await pgTestDatabase();
afterAll(() => db.close());
const { seedOwner } = await import("../../webhooks/testing/fixtures");
const { seedStoppedOnHost, seedStoredOffload } = await import("../testing/offload-fixtures");
const evict = await import("./evict");
const { discardFrames, settleDiscarded } = await import("./discard");
const { serverDiskMessageSchema } = await import("@wssp/sandbox-contracts");
const { detachToOffloaded } = await import("./detach");
const { assertHostDeletable, initializeHostMemoryReservation } = await import("../host-admission");
const { lockHostByEpoch } = await import("../relay-fence");
const {
  ACCOUNT_DELETION_CLASSIFICATION,
  AccountDeletionConflictError,
  deleteAccountInTransaction,
} = await import("@wssp/db/account-deletion");

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

/** A STOPPED sandbox cached on an eligible host, its disk STORED (seq 1). */
async function world() {
  const owner = await seedOwner(db.inspect);
  const { host, sandbox } = await seedStoppedOnHost(db.inspect, { userId: owner });
  const stored = await seedStoredOffload(db.inspect, {
    userId: owner,
    sandboxId: sandbox.id,
    hostId: host.id,
  });
  await db.inspect.sandboxDiskOffload.update({
    where: { id: stored.offloadId },
    data: { sourceGeneration: sandbox.generation },
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { diskOffloadId: stored.offloadId, cachedOffloadSeq: 1, offloadSeq: 1 },
  });
  const sender = (epoch = host.connectionEpoch) => ({
    userId: owner,
    hostId: host.id,
    connectionEpoch: epoch,
    isCurrent: () => true,
  });
  const ref = { sandboxId: sandbox.id, offloadId: stored.offloadId, seq: 1 };
  const request = (s = sender(), r = ref) =>
    db.prisma.$transaction((tx) => evict.grantEviction(tx, s, r));
  const offload = () =>
    db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: stored.offloadId } });
  const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
  const proof = async () => {
    const s = await row();
    return {
      storagePoolName: s.storagePoolName!,
      storageMarker: s.storageMarker!,
      diskGiB: s.diskGiB,
      state: "absent" as const,
      networkCleanupComplete: true,
      observationSequence: 0,
    };
  };
  const counters = async () => {
    const h = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } });
    const pools = await db.inspect.sandboxHostStoragePool.findMany({
      where: { sandboxHostId: host.id },
    });
    return { rootCount: h.rootCount, reserved: pools.reduce((n, p) => n + p.diskReservedGiB, 0) };
  };
  return { owner, host, sandbox, ref, sender, request, offload, row, proof, counters };
}

type World = Awaited<ReturnType<typeof world>>;

async function granted(w: World) {
  const frame = await w.request();
  expect(frame.type).toBe("disk.evict.grant");
  return frame as Extract<typeof frame, { type: "disk.evict.grant" }>;
}

const evicted = (w: World, m: Parameters<typeof evict.acceptEvicted>[2], s = w.sender()) =>
  db.prisma.$transaction((tx) => evict.acceptEvicted(tx, s, m));

describe("disk.evict.request: the evict CAS (§7 step 2, I4)", () => {
  it("grants a STORED copy: EVICTING with a grant fenced to this host and epoch for 10 minutes", async () => {
    const w = await world();
    const before = Date.now();
    const grant = await granted(w);
    const offload = await w.offload();
    expect(offload).toMatchObject({
      state: "EVICTING",
      evictGrantId: grant.grantId,
      evictHostId: w.host.id,
      evictGrantEpoch: w.host.connectionEpoch,
    });
    expect(grant.expiresAtUnixMs).toBe(offload.evictGrantExpiresAt!.getTime());
    expect(grant.expiresAtUnixMs - before).toBeGreaterThan(evict.EVICT_GRANT_TTL_MS - 60_000);
    // A second request while EVICTING is refused: one grant at a time.
    expect(await w.request()).toMatchObject({ type: "disk.evict.refused", code: "stale" });
  });

  it("R8: refused when no eligible restore host exists (the only host is draining)", async () => {
    const w = await world();
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { draining: true } });
    expect(await w.request()).toMatchObject({
      type: "disk.evict.refused",
      code: "no_restore_host",
    });
    expect((await w.offload()).state).toBe("STORED");
  });

  it("another own eligible host keeps an eviction possible though this one drains", async () => {
    const w = await world();
    await seedStoppedOnHost(db.inspect, { userId: w.owner });
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { draining: true } });
    expect((await w.request()).type).toBe("disk.evict.grant");
  });

  it.each([
    ["another seq", (w: World) => w.request(w.sender(), { ...w.ref, seq: 2 }), "stale"],
    [
      "another offload",
      (w: World) => w.request(w.sender(), { ...w.ref, offloadId: "off_x" }),
      "stale",
    ],
  ] as const)("refuses %s", async (_name, run, code) => {
    const w = await world();
    expect(await run(w)).toMatchObject({ type: "disk.evict.refused", code });
  });

  it("refuses a sandbox that is not STOPPED, or not cached at that seq", async () => {
    const w = await world();
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { cachedOffloadSeq: 2 } });
    expect(await w.request()).toMatchObject({ code: "stale" });
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { cachedOffloadSeq: 1, state: "STOPPING" },
    });
    expect(await w.request()).toMatchObject({ code: "stale" });
  });

  it("refuses with an operation in flight, and with an unretired UNKNOWN receipt (N4)", async () => {
    const w = await world();
    const op = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: w.owner,
        sandboxId: w.sandbox.id,
        kind: "RUN_COMMAND",
        state: "QUEUED",
        generation: w.sandbox.generation,
        idempotencyKey: `k-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
      },
    });
    expect(await w.request()).toMatchObject({ code: "operation_in_flight" });
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { state: "UNKNOWN_OUTCOME" },
    });
    expect(await w.request()).toMatchObject({ code: "receipt_unretired" });
    expect((await w.offload()).state).toBe("STORED");
  });

  it("refuses while a capture copies the stopped root", async () => {
    const w = await world();
    const op = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: w.owner,
        sandboxId: w.sandbox.id,
        kind: "RUN_COMMAND",
        state: "SUCCEEDED",
        generation: w.sandbox.generation,
        idempotencyKey: `k-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
      },
    });
    const sandbox = await w.row();
    await db.inspect.sandboxTemplateCapture.create({
      data: {
        operationId: op.id,
        userId: w.owner,
        sandboxId: w.sandbox.id,
        templateId: sandbox.templateId,
        tag: "v2",
        hostId: w.host.id,
        hostOwnerId: w.owner,
        state: "PENDING",
      },
    });
    expect(await w.request()).toMatchObject({ code: "capture_busy" });
  });

  it("`off` stops evictions (I9)", async () => {
    const w = await world();
    process.env.SANDBOX_OFFLOAD = "off";
    try {
      expect(await w.request()).toMatchObject({ code: "offload_disabled" });
    } finally {
      process.env.SANDBOX_OFFLOAD = "auto";
    }
  });

  it("a fenced (stale epoch) session takes no grant", async () => {
    const w = await world();
    await expect(w.request(w.sender(w.host.connectionEpoch + 1))).rejects.toThrow();
    expect((await w.offload()).state).toBe("STORED");
  });
});

describe("disk.evicted: the grant fence (§7 step 6)", () => {
  it("only the matching grant from the granted host detaches; root released once; epoch may differ", async () => {
    const w = await world();
    const grant = await granted(w);
    const before = await w.counters();
    const base = { sandboxId: w.sandbox.id, offloadId: w.ref.offloadId };
    expect(
      await evicted(w, { ...base, grantId: "evg_other", rootAbsenceProof: await w.proof() }),
    ).toBe("refused");
    // A proof of another root is not a proof.
    expect(
      await evicted(w, {
        ...base,
        grantId: grant.grantId,
        rootAbsenceProof: { ...(await w.proof()), storageMarker: "f".repeat(32) },
      }),
    ).toBe("refused");
    expect(
      await evicted(w, {
        ...base,
        grantId: grant.grantId,
        rootAbsenceProof: { ...(await w.proof()), networkCleanupComplete: false },
      }),
    ).toBe("refused");
    // Another host never completes it.
    const other = await seedStoppedOnHost(db.inspect, { userId: w.owner });
    expect(
      await evicted(
        w,
        { ...base, grantId: grant.grantId, rootAbsenceProof: await w.proof() },
        {
          userId: w.owner,
          hostId: other.host.id,
          connectionEpoch: other.host.connectionEpoch,
          isCurrent: () => true,
        },
      ),
    ).toBe("refused");
    expect((await w.row()).state).toBe("STOPPED");
    // The granted host after a reconnect (new epoch) completes it.
    const host = await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: { connectionEpoch: { increment: 1 } },
    });
    const proof = await w.proof();
    expect(
      await evicted(
        w,
        { ...base, grantId: grant.grantId, rootAbsenceProof: proof },
        w.sender(host.connectionEpoch),
      ),
    ).toBe("ack");
    const row = await w.row();
    expect(row).toMatchObject({
      state: "OFFLOADED",
      sandboxHostId: null,
      hostOwnerId: null,
      currentPlacementId: null,
      storagePoolId: null,
      diskReservationHeld: false,
      liveResourcesHeld: false,
      leaseExpiresAt: null,
      diskOffloadId: w.ref.offloadId,
      generation: w.sandbox.generation + 1,
    });
    expect(await w.offload()).toMatchObject({
      state: "STORED",
      evictGrantId: null,
      evictHostId: null,
    });
    const after = await w.counters();
    expect(after.rootCount).toBe(before.rootCount - 1);
    expect(after.reserved).toBeLessThan(before.reserved);
    // A repeated report is acked again and releases nothing more.
    expect(
      await evicted(
        w,
        { ...base, grantId: grant.grantId, rootAbsenceProof: proof },
        w.sender(host.connectionEpoch),
      ),
    ).toBe("ack");
    expect(await w.counters()).toEqual(after);
  });
});

describe("expired grant without proof", () => {
  it("the granting session outliving its grant clears the marker; a reconnected host is left to its census", async () => {
    const w = await world();
    await granted(w);
    const expiresAt = (await w.offload()).evictGrantExpiresAt!;
    const later = new Date(expiresAt.getTime() + evict.EVICT_GRANT_OUTLIVED_MS + 1000);
    // Not yet outlived: kept.
    expect(await evict.clearOutlivedEvictGrants(new Date(expiresAt.getTime() + 1000))).toBe(0);
    // The host reconnected since (another epoch): kept for the census.
    await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: { connectionEpoch: { increment: 1 } },
    });
    await evict.clearOutlivedEvictGrants(later);
    expect((await w.offload()).state).toBe("EVICTING");
    await db.inspect.sandboxHost.update({
      where: { id: w.host.id },
      data: { connectionEpoch: { decrement: 1 } },
    });
    expect(await evict.clearOutlivedEvictGrants(later)).toBeGreaterThanOrEqual(1);
    expect(await w.offload()).toMatchObject({ state: "STORED", evictGrantId: null });
    // The daemon refused the grant: the copy is unusable, so its next start
    // discards it and restores instead of asking for another grant.
    expect(await w.row()).toMatchObject({ state: "STOPPED", cachedOffloadSeq: null });
  });
});

/** Detach `w`'s sandbox to OFFLOADED leaving a STALE copy on its host. */
async function staleCopy(w: World) {
  const s = await w.row();
  await db.prisma.$transaction(async (tx) => {
    await lockHostByEpoch(tx, w.host.id, w.host.connectionEpoch, w.owner);
    expect(
      await detachToOffloaded(tx, {
        sandboxId: s.id,
        userId: s.userId,
        hostId: w.host.id,
        generation: s.generation,
        proof: {
          kind: "stale_copy",
          createKey: "create-key-1",
          baseFingerprint: `sha256:${"b".repeat(64)}`,
        },
      }),
    ).toBe(true);
  });
  return db.inspect.sandboxDiskCopy.findFirstOrThrow({ where: { sandboxId: s.id } });
}

describe("stale copies (§7 census rule, S8 discard, I5)", () => {
  it("a stale detach moves the hold to the copy row: counters unchanged, OFFLOADED", async () => {
    const w = await world();
    const before = await w.counters();
    const s = await w.row();
    const copy = await staleCopy(w);
    expect(copy).toMatchObject({
      state: "STALE",
      hostId: w.host.id,
      hostOwnerId: w.owner,
      storagePoolId: s.storagePoolId,
      storageMarker: s.storageMarker,
      storagePoolName: s.storagePoolName,
      rootChargeGiB: s.rootChargeGiB,
      createKey: "create-key-1",
      diskReservationHeld: true,
      offloadSeq: 1,
    });
    expect(await w.counters()).toEqual(before);
    expect((await w.row()).state).toBe("OFFLOADED");
  });

  it("the reservation rebuild sums copy rows; the host cannot be deleted while one remains", async () => {
    const w = await world();
    await staleCopy(w);
    const before = await w.counters();
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { rootCount: 0 } });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: w.host.id },
      data: { diskReservedGiB: 0 },
    });
    await db.prisma.$transaction(async (tx) => {
      await lockHostByEpoch(tx, w.host.id, w.host.connectionEpoch, w.owner);
      await initializeHostMemoryReservation(tx, w.host.id, w.owner);
    });
    expect(await w.counters()).toEqual(before);
    await expect(
      db.prisma.$transaction((tx) => assertHostDeletable(tx, w.host.id, w.owner)),
    ).rejects.toThrow(/stale disk copies/);
  });

  it("discard: a refusal keeps the row; a matching root proof releases once and deletes it", async () => {
    const w = await world();
    const copy = await staleCopy(w);
    const before = await w.counters();
    const settle = (m: Parameters<typeof settleDiscarded>[2]) =>
      db.prisma.$transaction((tx) => settleDiscarded(tx, w.sender(), m));
    expect(
      await settle({ sandboxId: w.sandbox.id, copyId: copy.id, code: "binding_mismatch" }),
    ).toBe("refused");
    // A proof of another root never releases.
    const proof = {
      storagePoolName: copy.storagePoolName,
      storageMarker: copy.storageMarker,
      diskGiB: w.sandbox.diskGiB,
      state: "absent" as const,
      networkCleanupComplete: true,
      observationSequence: 0,
    };
    expect(
      await settle({
        sandboxId: w.sandbox.id,
        copyId: copy.id,
        rootAbsenceProof: { ...proof, storagePoolName: "other" },
      }),
    ).toBe("refused");
    expect(await w.counters()).toEqual(before);
    expect(
      await settle({ sandboxId: w.sandbox.id, copyId: copy.id, rootAbsenceProof: proof }),
    ).toBe("released");
    expect(await db.inspect.sandboxDiskCopy.count({ where: { id: copy.id } })).toBe(0);
    const after = await w.counters();
    expect(after.rootCount).toBe(before.rootCount - 1);
    expect(after.reserved).toBe(before.reserved - copy.rootChargeGiB);
    // Repeated: the row is gone, nothing more is released.
    expect(
      await settle({ sandboxId: w.sandbox.id, copyId: copy.id, rootAbsenceProof: proof }),
    ).toBe("unknown");
    expect(await w.counters()).toEqual(after);
    // With no copy left the host is deletable again (nothing else holds it).
    await db.prisma.$transaction((tx) => assertHostDeletable(tx, w.host.id, w.owner));
  });

  it("a discard frame names the copy's base and the sandbox's template revision", async () => {
    const w = await world();
    const copy = await staleCopy(w);
    const restored = `sha256:${"d".repeat(64)}`;
    await db.inspect.sandboxDiskCopy.update({
      where: { id: copy.id },
      data: { baseFingerprint: restored },
    });
    const revision = await db.inspect.sandboxTemplateRevision.findFirstOrThrow({
      where: { id: w.sandbox.templateRevisionId },
      select: { incusFingerprint: true },
    });
    const frames = (await discardFrames(new Date())).filter(
      (f) => f.frame.type === "disk.discard" && f.frame.sandboxId === w.sandbox.id,
    );
    expect(frames.map((f) => f.frame)).toEqual([
      {
        type: "disk.discard",
        sandboxId: w.sandbox.id,
        copyId: copy.id,
        createKey: "create-key-1",
        baseFingerprint: restored,
        templateFingerprint: revision.incusFingerprint,
        storagePoolName: copy.storagePoolName,
        storageMarker: copy.storageMarker,
      },
    ]);
    expect(serverDiskMessageSchema.safeParse(frames[0]!.frame).success).toBe(true);
  });

  it("S10: a copy row blocks account deletion until discarded", async () => {
    const w = await world();
    await staleCopy(w);
    const entry = ACCOUNT_DELETION_CLASSIFICATION.find((t) => t.model === "SandboxDiskCopy");
    expect(entry?.class).toBe("blocker");
    // Deleting the account while the copy holds a root is refused.
    await expect(
      db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, w.owner)),
    ).rejects.toBeInstanceOf(AccountDeletionConflictError);
    expect(await db.inspect.sandboxDiskCopy.count({ where: { userId: w.owner } })).toBe(1);
    const blocker = entry as { hasLive: (tx: unknown, ownerId: string) => Promise<boolean> };
    expect(await db.prisma.$transaction((tx) => blocker.hasLive(tx, w.owner))).toBe(true);
  });

  it("a stale copy excludes its host from restore eligibility (R9)", async () => {
    const w = await world();
    await staleCopy(w);
    const { RESTORE_SANDBOX_FACTS_SELECT, restoreHostEligibility } = await import("./eligibility");
    const facts = await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: w.sandbox.id },
      select: RESTORE_SANDBOX_FACTS_SELECT,
    });
    expect(
      await db.prisma.$transaction((tx) =>
        restoreHostEligibility(tx, facts, { hostId: w.host.id }),
      ),
    ).toEqual({ ok: false, reason: "stale_copy_on_host" });
  });
});
