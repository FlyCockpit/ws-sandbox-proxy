import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { seedAcceptedOperation } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-handlers-test-key",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeImageGrantBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
}));

const { handleImageCached, handleImageCensus, handleImageFetchRequest } = await import(
  "./image-handlers"
);
const { foreignImageAccessLost } = await import("@wssp/api/sandbox/image-store/access");
const { initializeHostMemoryReservation } = await import("@wssp/api/sandbox/host-admission");
const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
const { seedLaunchHost, seedTemplateRevision } = await import(
  "../../../../packages/api/src/sandbox/testing/resource-fixtures"
);

const db = await pgTestDatabase();
afterAll(() => db.close());

const FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: true,
    leaseFromReady: false,
    captureStorageMarkers: [],
  },
};

async function user() {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "U", email: `${id}@example.test` } });
  return id;
}

function ctx(sender: { userId: string; hostId: string; connectionEpoch: number }) {
  const replies: unknown[] = [];
  return {
    replies,
    ctx: {
      sender: { ...sender, isCurrent: () => true },
      reply: (frame: unknown) => replies.push(frame),
      sendTo: () => true,
      isHostCurrent: () => true,
      spool: {} as never,
    },
  };
}

describe("host image frames against real PostgreSQL", () => {
  it("M4/P1-2: image.cached from an unrelated or ungranted operation records nothing", async () => {
    const hostOwner = await user();
    const stranger = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: hostOwner,
        slug: "h",
        label: "h",
        status: "CONNECTED",
        daemonFeatures: FEATURES,
        imageCacheEpoch: 1,
        imageCacheCapBytes: 1n << 34n,
        imageCacheUsedBytes: 0n,
        imageCacheForeignBytes: 0n,
      },
    });
    const fp = `sha256:${"e".repeat(64)}`;
    const revision = await seedTemplateRevision(db.inspect, {
      data: { userId: stranger, slug: "s", label: "S", incusFingerprint: fp },
    });
    const { ctx: frameCtx } = ctx({ userId: hostOwner, hostId: host.id, connectionEpoch: 1 });
    const frame = {
      type: "image.cached" as const,
      fingerprint: fp,
      imageOwnerId: stranger,
      operationId: "not-an-operation-here",
      compressedBytes: 100,
      origin: "fetched" as const,
      totals: { usedBytes: 100, foreignBytes: 100 },
    };
    await handleImageCached(frameCtx, frame);
    expect(
      await db.inspect.sandboxTemplateAvailability.count({
        where: { hostId: host.id, userId: stranger },
      }),
    ).toBe(0);
    expect(await db.inspect.sandboxHostImageCache.count({ where: { hostId: host.id } })).toBe(0);
    // A create of that owner dispatched to this host is the job that proves it.
    const sandbox = await db.inspect.sandbox.create({
      data: {
        userId: stranger,
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        originalSelector: "x",
        originHostId: host.id,
        hostOwnerId: host.userId,
      },
    });
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: stranger,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "RUNNING",
        generation: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "h",
        dispatchedHostId: host.id,
        dispatchedConnectionEpoch: 1,
      },
    });
    // A create dispatched here is not enough on its own (P1-2): it proves an
    // image only through its own granted fetch of exactly that fingerprint.
    // The positive path is covered in image-authority.pg.test.ts.
    await handleImageCached(frameCtx, { ...frame, operationId: op.id });
    expect(
      await db.inspect.sandboxTemplateAvailability.count({
        where: { hostId: host.id, userId: stranger },
      }),
    ).toBe(0);
    expect(await db.inspect.sandboxHostImageCache.count({ where: { hostId: host.id } })).toBe(0);
  });

  it("a fetch request for an operation not dispatched to this host on this epoch is refused", async () => {
    const owner = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: { userId: owner, slug: "f", label: "f", status: "CONNECTED", daemonFeatures: FEATURES },
    });
    const { ctx: frameCtx, replies } = ctx({ userId: owner, hostId: host.id, connectionEpoch: 1 });
    await handleImageFetchRequest(frameCtx, {
      type: "image.fetch.request",
      requestId: "r1",
      operationId: "op-missing",
      sandboxId: "sbx",
      generation: 1,
      attempt: 1,
      fingerprint: `sha256:${"f".repeat(64)}`,
      resumeOffset: 0,
    });
    expect(replies).toEqual([
      { type: "image.fetch.refused", requestId: "r1", code: "stale_operation" },
    ]);
  });

  it("M3: the boot recompute keeps a running capture's hold on the host counters", async () => {
    const owner = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: { userId: owner, slug: "c", label: "c", status: "CONNECTED", daemonFeatures: FEATURES },
    });
    const revision = await seedTemplateRevision(db.inspect, {
      data: { userId: owner, slug: "c", label: "C", incusFingerprint: `sha256:${"9".repeat(64)}` },
    });
    const sandbox = await db.inspect.sandbox.create({
      data: {
        userId: owner,
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        originalSelector: "x",
        originHostId: host.id,
        hostOwnerId: host.userId,
        state: "DELETED",
      },
    });
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: owner,
        sandboxId: sandbox.id,
        kind: "CAPTURE_TEMPLATE",
        state: "RUNNING",
        generation: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "h",
      },
    });
    await db.inspect.sandboxTemplateCapture.create({
      data: {
        operationId: op.id,
        userId: owner,
        sandboxId: sandbox.id,
        templateId: revision.templateId,
        tag: "latest",
        hostId: host.id,
        hostOwnerId: owner,
        resourcesHeld: true,
        chargedMemoryMiB: 1280,
        chargedVcpu: 1,
      },
    });
    await db.inspect.$transaction(async (tx) => {
      await lockHostByEpoch(tx, host.id, 1, owner);
      await initializeHostMemoryReservation(tx, host.id, owner);
    });
    const after = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } });
    expect([after.memoryReservedMiB, after.vcpuReserved]).toEqual([1280, 1]);
  });

  it("round-2 P1-1: replaying a historical COMPLETE fetch never revives a foreign copy whose access was revoked", async () => {
    const hostOwner = await user();
    const imageOwner = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: hostOwner,
        slug: "fx",
        label: "fx",
        status: "CONNECTED",
        daemonFeatures: FEATURES,
        imageCacheEpoch: 1,
        imageCacheCapBytes: 1n << 34n,
        imageCacheUsedBytes: 0n,
        imageCacheForeignBytes: 0n,
      },
    });
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: hostOwner, slug: "p", label: "P" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: hostOwner, hostOwnerId: hostOwner, poolId: pool.id, sandboxHostId: host.id },
    });
    await db.inspect.share.create({
      data: { poolId: pool.id, ownerUserId: hostOwner, granteeUserId: imageOwner },
    });
    const fp = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "7")}`;
    const revision = await seedTemplateRevision(db.inspect, {
      data: { userId: imageOwner, slug: "r", label: "R", incusFingerprint: fp },
    });
    const transfer = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: imageOwner,
        fingerprint: fp,
        purpose: "FETCH",
        mode: "S3",
        destHostId: host.id,
        destHostOwnerId: hostOwner,
        destEpoch: 1,
        state: "COMPLETE",
        sizeBytes: 4096n,
        partSize: 4096,
        partCount: 1,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    const { ctx: frameCtx, replies } = ctx({
      userId: hostOwner,
      hostId: host.id,
      connectionEpoch: 1,
    });
    const frame = {
      type: "image.cached" as const,
      fingerprint: fp,
      imageOwnerId: imageOwner,
      transferId: transfer.id,
      compressedBytes: 4096,
      origin: "fetched" as const,
      totals: { usedBytes: 4096, foreignBytes: 4096 },
    };
    const status = async () =>
      (
        await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
          where: { revisionId: revision.id, hostId: host.id },
        })
      ).status;
    await handleImageCached(frameCtx, frame);
    expect(await status()).toBe("AVAILABLE");
    // The owner switches to owned-nodes-only; the access scan revokes the copy.
    await db.inspect.accountImagePolicy.create({
      data: { userId: imageOwner, imagePlacement: "OWNED_NODES_ONLY" },
    });
    expect((await foreignImageAccessLost(host.id)).map((r) => r.fingerprint)).toEqual([fp]);
    expect(await status()).toBe("MISSING");
    // Replaying the same historical evidence is refused and the host told to release.
    await handleImageCached(frameCtx, frame);
    expect(await status()).toBe("MISSING");
    expect(replies.at(-1)).toEqual({
      type: "image.release",
      fingerprint: fp,
      imageOwnerId: imageOwner,
      reason: "access_lost",
    });
    const row = await db.inspect.sandboxHostImageCache.findFirstOrThrow({
      where: { hostId: host.id, imageOwnerId: imageOwner },
    });
    expect(row.accessLostAt).not.toBeNull();
  });

  it("E2-A-01: a census of a foreign origin pin no capture recorded releases it, unless a capture may still name it", async () => {
    const hostOwner = await user();
    const builder = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: hostOwner,
        slug: "census",
        label: "census",
        status: "CONNECTED",
        daemonFeatures: FEATURES,
        imageCacheEpoch: 1,
        imageCacheCapBytes: 1n << 34n,
        imageCacheUsedBytes: 0n,
        imageCacheForeignBytes: 0n,
      },
    });
    const fp = `sha256:${"d".repeat(64)}`;
    const census = {
      type: "image.cache.census" as const,
      page: 0,
      complete: true,
      entries: [
        {
          fingerprint: fp,
          owners: [builder],
          compressedBytes: 100,
          origin: "captured" as const,
          pinned: true,
        },
      ],
      totals: { usedBytes: 100, foreignBytes: 100 },
    };
    const release = { type: "image.release", fingerprint: fp, imageOwnerId: builder, reason: "gc" };
    // An unrecorded capture of that account on this host may name the image.
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: builder,
        slug: "b",
        label: "B",
        incusFingerprint: `sha256:${"c".repeat(64)}`,
      },
    });
    const sandbox = await db.inspect.sandbox.create({
      data: {
        userId: builder,
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        originalSelector: "x",
        originHostId: host.id,
        hostOwnerId: host.userId,
      },
    });
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: builder,
        sandboxId: sandbox.id,
        kind: "CAPTURE_TEMPLATE",
        state: "RUNNING",
        generation: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "h",
        dispatchedHostId: host.id,
        dispatchedConnectionEpoch: 1,
      },
    });
    await db.inspect.sandboxTemplateCapture.create({
      data: {
        operationId: op.id,
        userId: builder,
        sandboxId: sandbox.id,
        templateId: revision.templateId,
        tag: "latest",
        hostId: host.id,
        hostOwnerId: hostOwner,
      },
    });
    const pending = ctx({ userId: hostOwner, hostId: host.id, connectionEpoch: 1 });
    await handleImageCensus(pending.ctx, census, { seen: new Set(), startedAt: null });
    expect(pending.replies).not.toContainEqual(release);
    // The capture lost (its result was dropped): the copy is released.
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: { state: "FAILED", finalizedAt: new Date() },
    });
    const ended = ctx({ userId: hostOwner, hostId: host.id, connectionEpoch: 1 });
    await handleImageCensus(ended.ctx, census, { seen: new Set(), startedAt: null });
    expect(ended.replies).toContainEqual(release);
    // The census itself still records no foreign evidence (M4).
    expect(await db.inspect.sandboxHostImageCache.count({ where: { hostId: host.id } })).toBe(0);
  });

  it("a complete census never deletes a copy recorded after its run began (periodic census)", async () => {
    const hostOwner = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: hostOwner,
        slug: "census-run",
        label: "census-run",
        status: "CONNECTED",
        daemonFeatures: FEATURES,
        imageCacheEpoch: 1,
        imageCacheCapBytes: 1n << 34n,
        imageCacheUsedBytes: 0n,
        imageCacheForeignBytes: 0n,
      },
    });
    const row = (fingerprint: string, reportedAt: Date) =>
      db.inspect.sandboxHostImageCache.create({
        data: {
          hostId: host.id,
          hostOwnerId: hostOwner,
          imageOwnerId: hostOwner,
          fingerprint,
          compressedBytes: 100n,
          origin: "captured",
          pinned: true,
          connectionEpoch: 1,
          reportedAt,
        },
      });
    const gone = `sha256:${"1".repeat(64)}`;
    const fresh = `sha256:${"2".repeat(64)}`;
    await row(gone, new Date(Date.now() - 60_000));
    const page = (n: number, complete: boolean) => ({
      type: "image.cache.census" as const,
      page: n,
      complete,
      entries: [],
      totals: { usedBytes: 0, foreignBytes: 0 },
    });
    const run = { seen: new Set<string>(), startedAt: null };
    const { ctx: frameCtx } = ctx({ userId: hostOwner, hostId: host.id, connectionEpoch: 1 });
    await handleImageCensus(frameCtx, page(0, false), run);
    // A capture finalized mid-run writes its origin row after the host's
    // census pages were built.
    await row(fresh, new Date(Date.now() + 1_000));
    await handleImageCensus(frameCtx, page(1, true), run);
    const left = await db.inspect.sandboxHostImageCache.findMany({
      where: { hostId: host.id },
      select: { fingerprint: true },
    });
    expect(left).toEqual([{ fingerprint: fresh }]);
  });
});
