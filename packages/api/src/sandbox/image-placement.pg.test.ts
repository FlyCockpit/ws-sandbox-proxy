import { digestContextSnapshot } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-placement-fixture",
  },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { directFetchDecision, imageFetchPlan } from "./image-placement";
import { applyCaptureRetention } from "./image-store/captures";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

const GIB = 1n << 30n;
const FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: false,
    leaseFromReady: false,
    captureStorageMarkers: [],
  },
};

async function user() {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "U", email: `${id}@example.test` } });
  return id;
}

async function host(userId: string, slug: string, features: object = FEATURES, cap = 10n * GIB) {
  return seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug,
      label: slug,
      status: "CONNECTED",
      egressEnforcement: true,
      daemonFeatures: features,
      imageCacheCapBytes: cap,
      imageCacheUsedBytes: 0n,
      imageCacheForeignBytes: 0n,
      imageCacheEpoch: 1,
    },
  });
}

/** Owner with a source host holding a registered revision, plus an empty target. */
async function fixture(size: bigint | null = 3n * GIB, format: string | null = null) {
  const owner = await user();
  const source = await host(owner, "source");
  const target = await host(owner, "target");
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: owner,
      sandboxHostId: source.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "0")}`,
    },
  });
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId: revision.id, hostId: source.id },
    data: { sizeBytes: size, imageFormat: format },
  });
  return { owner, source, target, revision };
}

/** An in-flight create of `owner`'s image on `targetId` with a planned fetch. */
async function plannedFetch(
  owner: Awaited<ReturnType<typeof fixture>>,
  targetId: string,
  bytes: bigint,
) {
  const target = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: targetId } });
  const sandbox = await db.inspect.sandbox.create({
    data: {
      userId: owner.owner,
      hostOwnerId: target.userId,
      templateId: owner.revision.templateId,
      templateRevisionId: owner.revision.id,
      originalSelector: "x",
      originHostId: targetId,
      storagePoolId: "fixture-pool",
      storageMarker: "fixture-marker",
      storagePoolName: "default",
      rootChargeGiB: 33,
    },
  });
  const config = await db.inspect.sandboxExecutionConfig.create({
    data: {
      id: randomUUID(),
      userId: owner.owner,
      sandboxId: sandbox.id,
      generation: 1,
      hostId: targetId,
      templateDefaults: {},
      sandboxOverrides: {},
      mergedDefaults: {},
      bindingScheme: "hmac-sha256-v1",
      bindingKeyId: "a".repeat(32),
      bindingMac: "b".repeat(64),
    },
  });
  const op = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v1" }),
      ...requestDigestMetadata(),

      userId: owner.owner,
      sandboxId: sandbox.id,
      kind: "CREATE_SANDBOX",
      state: "DISPATCHED",
      generation: 1,
      idempotencyKey: randomUUID(),
      requestBodyHash: "h",
    },
  });
  await db.inspect.sandboxPlacement.create({
    data: {
      userId: owner.owner,
      hostOwnerId: target.userId,
      sandboxId: sandbox.id,
      generation: 1,
      operationId: op.id,
      kind: "DIRECT",
      originHostId: targetId,
      storagePoolId: "fixture-pool",
      storageMarker: "fixture-marker",
      storagePoolName: "default",
      rootChargeGiB: 33,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
      templateId: owner.revision.templateId,
      templateRevisionId: owner.revision.id,
      artifact: owner.revision.incusFingerprint,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      configId: config.id,
      acceptedAt: new Date(),
      imageFetchBytes: bytes,
    },
  });
  return op;
}

async function decide(
  owner: string,
  target: { id: string; userId: string; daemonFeatures: unknown },
  revision: { templateId: string; incusFingerprint: string; architecture: string },
  pool: { poolOwnerId: string; memberCapGiB: number | null } | null = null,
) {
  const row = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: target.id } });
  return db.inspect.$transaction((tx) =>
    directFetchDecision(tx, {
      ownerId: owner,
      hostId: target.id,
      hostOwnerId: target.userId,
      revision,
      daemonFeatures: row.daemonFeatures,
      now: new Date(),
      ...(pool ? { poolOwnerId: pool.poolOwnerId, memberCapGiB: pool.memberCapGiB } : {}),
    }),
  );
}

describe("image fetch placement against real PostgreSQL", () => {
  it("M5: a registered unified (or not yet known) revision with a reported size is fetchable; a split or sizeless one is not", async () => {
    const ok = await fixture();
    const plan = await db.inspect.$transaction((tx) => imageFetchPlan(tx, ok.owner, ok.revision));
    expect(plan).toMatchObject({ mode: "peer", sizeBytes: 3n * GIB, policy: "ANY_NODE" });
    expect(await decide(ok.owner, ok.target, ok.revision)).not.toBeNull();
    const sizeless = await fixture(null);
    expect(await decide(sizeless.owner, sizeless.target, sizeless.revision)).toBeNull();
    const split = await fixture(3n * GIB, "split");
    expect(await decide(split.owner, split.target, split.revision)).toBeNull();
  });

  it("an offline source or a stale cache epoch makes the fetch inadmissible now", async () => {
    const f = await fixture();
    await db.inspect.sandboxHost.update({
      where: { id: f.source.id },
      data: { status: "DISCONNECTED" },
    });
    expect(await decide(f.owner, f.target, f.revision)).toBeNull();
    const g = await fixture();
    await db.inspect.sandboxHost.update({
      where: { id: g.target.id },
      data: { imageCacheEpoch: 0 },
    });
    expect(await decide(g.owner, g.target, g.revision)).toBeNull();
  });

  it("M6: other in-flight fetch-planned creates reserve headroom until they end", async () => {
    const f = await fixture(6n * GIB);
    // Another create on the target already planned an 8 GiB fetch of a different image.
    const other = await fixture(8n * GIB);
    const op = await plannedFetch(other, f.target.id, 8n * GIB);
    // 10 GiB cap − 8 GiB reserved < 6 GiB: no headroom for the second fetch.
    expect(await decide(f.owner, f.target, f.revision)).toBeNull();
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { state: "SUCCEEDED" },
    });
    expect(await decide(f.owner, f.target, f.revision)).not.toBeNull();
  });

  it("foreign hosts: accept_foreign, the owned-only policy and the pool member cap all gate a fetch", async () => {
    const f = await fixture(2n * GIB);
    const stranger = await user();
    const refusing = await host(stranger, "refusing");
    expect(await decide(f.owner, refusing, f.revision)).toBeNull();
    const accepting = await host(stranger, "accepting", {
      ...FEATURES,
      image: { ...FEATURES.image, acceptForeign: true },
    });
    expect(await decide(f.owner, accepting, f.revision)).not.toBeNull();
    // Member cap counts all other accounts' bytes on the member (minor 10).
    await db.inspect.sandboxHost.update({
      where: { id: accepting.id },
      data: { imageCacheForeignBytes: 1n * GIB },
    });
    expect(
      await decide(f.owner, accepting, f.revision, { poolOwnerId: f.owner, memberCapGiB: 2 }),
    ).toBeNull();
    expect(
      await decide(f.owner, accepting, f.revision, { poolOwnerId: f.owner, memberCapGiB: 3 }),
    ).not.toBeNull();
    await db.inspect.sandboxTemplate.update({
      where: { id: f.revision.templateId },
      data: { imagePlacement: "OWNED_NODES_ONLY" },
    });
    expect(await decide(f.owner, accepting, f.revision)).toBeNull();
    // Owned hosts are unaffected by the owned-only policy.
    expect(await decide(f.owner, f.target, f.revision)).not.toBeNull();
  });

  it("P2-7: the pool member cap counts other accounts' fetches already planned onto the member", async () => {
    const f = await fixture(2n * GIB);
    const stranger = await user();
    const member = await host(stranger, "member", {
      ...FEATURES,
      image: { ...FEATURES.image, acceptForeign: true },
    });
    // A contributed member (the pool belongs to another account).
    const pool = { poolOwnerId: f.owner, memberCapGiB: 3 };
    expect(await decide(f.owner, member, f.revision, pool)).not.toBeNull();
    // A third account's 2 GiB fetch is already planned onto the member:
    // 0 reported + 2 pending + 2 requested > 3 GiB.
    const third = await fixture(2n * GIB);
    const op = await plannedFetch(third, member.id, 2n * GIB);
    expect(await decide(f.owner, member, f.revision, pool)).toBeNull();
    // Once that create ends its planned bytes no longer count.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { state: "SUCCEEDED" },
    });
    expect(await decide(f.owner, member, f.revision, pool)).not.toBeNull();
  });

  it("capture retention keeps the newest N of a tag and never a revision another tag points to", async () => {
    const f = await fixture();
    const base = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: f.revision.id },
    });
    const made: string[] = [];
    for (let n = 2; n <= 6; n++) {
      const r = await db.inspect.sandboxTemplateRevision.create({
        data: {
          userId: f.owner,
          templateId: base.templateId,
          revision: n,
          incusFingerprint: base.incusFingerprint,
          architecture: base.architecture,
          manifestDigest: `${n}`.padEnd(64, "0"),
          sourceKind: "CAPTURE",
          captureTag: "nightly",
        },
      });
      made.push(r.id);
    }
    // Revision 2 is also tagged `pinned`, so retention must skip it.
    await db.inspect.sandboxTemplateTag.create({
      data: { userId: f.owner, templateId: base.templateId, tag: "pinned", revisionId: made[0]! },
    });
    await db.inspect.$transaction((tx) =>
      applyCaptureRetention(tx, {
        ownerId: f.owner,
        templateId: base.templateId,
        tag: "nightly",
        keep: 2,
        now: new Date(),
      }),
    );
    const rows = await db.inspect.sandboxTemplateRevision.findMany({
      where: { id: { in: made } },
      orderBy: { revision: "asc" },
      select: { revision: true, retiredAt: true, retiredReason: true },
    });
    expect(rows.map((r) => [r.revision, r.retiredReason])).toEqual([
      [2, null],
      [3, "retention"],
      [4, "retention"],
      [5, null],
      [6, null],
    ]);
  });

  it("a one-time relay link is consumed by exactly one of two concurrent presentations", async () => {
    const f = await fixture();
    const transfer = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: f.owner,
        fingerprint: f.revision.incusFingerprint,
        purpose: "FETCH",
        mode: "RELAY",
        sizeBytes: 10n,
        partSize: 10,
        partCount: 1,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const link = await db.inspect.sandboxImageLink.create({
      data: {
        transferId: transfer.id,
        hostId: f.target.id,
        hostEpoch: 1,
        role: "DEST",
        partNumber: 1,
        tokenDigest: "d".repeat(64),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const consume = () =>
      db.inspect.$queryRaw<{ id: string }[]>`DELETE FROM sandbox_image_link
        WHERE id = ${link.id} AND "tokenDigest" = ${"d".repeat(64)} AND "expiresAt" > now()
        RETURNING id`;
    const results = await Promise.all([consume(), consume()]);
    expect(results.map((r) => r.length).sort()).toEqual([0, 1]);
  });
});
