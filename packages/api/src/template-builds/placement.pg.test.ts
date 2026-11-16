vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-placement-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
const image = vi.hoisted(() => ({ mode: "s3" as "off" | "peer" | "s3" }));
vi.mock("../sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("../sandbox/image-store/config")>()),
  imageDistributionMode: () => image.mode,
}));

/**
 * Template builds pg 9: the `builder` placement stage, the target
 * policy, the `lease` skip reason, the opt-in read under owner placement, and
 * the capacity queue's build head (`headEligibleHosts`, r2 N11).
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { HEAD_BYPASS_LIMIT } from "../sandbox/capacity-limits";
import { reservedHostIds } from "../sandbox/capacity-queue";
import { lockOwnerPlacement } from "../sandbox/direct-placement";
import { resolvePlacement } from "../sandbox/pool-placement";
import { createSandbox } from "../sandbox/services/sandboxes";
import { lockPlacementPrincipals } from "../sandbox/sharing-authority";
import { poolFixture } from "../sandbox/testing/pool-fixtures";
import { seedLaunchHost, seedTemplateRevision } from "../sandbox/testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
beforeEach(() => {
  image.mode = "s3";
});

const HEX = "a".repeat(64);
const IMAGE = {
  fetch: true,
  serve: true,
  publish: true,
  capture: true,
  acceptForeign: false,
  leaseFromReady: false,
  formats: ["unified"],
  captureStorageMarkers: [],
};
type Flags = { build?: boolean; acceptForeignBuilds?: boolean; acceptForeign?: boolean };

async function setFlags(hostId: string, flags: Flags) {
  await db.inspect.sandboxHost.update({
    where: { id: hostId },
    data: { daemonFeatures: { egressPolicy: true, terminal: true, image: { ...IMAGE, ...flags } } },
  });
}

async function seedBuild(
  userId: string,
  templateId: string,
  baseRevisionId: string,
  poolId: string,
) {
  const id = randomUUID();
  await db.inspect.sandboxTemplateBuild.create({
    data: {
      id,
      userId,
      templateId,
      tag: "latest",
      principalKind: "session",
      idempotencyKey: id,
      requestBodyHash: "hash",
      recipe: { v: 1 },
      recipeDigest: HEX,
      buildDigest: "b".repeat(64),
      sourceFormat: "RECIPE",
      baseRevisionId,
      baseFingerprint: `sha256:${HEX}`,
      poolId,
      targetKey: poolId,
      principalKey: "s",
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 8,
      defaultDiskGiB: 8,
      timeoutMinutes: 60,
      reservedMinutes: 60,
      chargeMonth: new Date("2026-11-01T00:00:00Z"),
      state: "QUEUED",
    },
  });
  return id;
}

/**
 * Requester (grantee) with one own host contributed to a pool owned by
 * another account whose two hosts are foreign to the requester.
 */
async function sharedPool() {
  const f = await poolFixture(db);
  const grantee = randomUUID();
  await db.inspect.user.create({
    data: {
      id: grantee,
      name: "Builder",
      email: `${grantee}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const share = await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: grantee, canContribute: true },
  });
  const own = await seedLaunchHost(db.inspect, {
    data: {
      userId: grantee,
      slug: "own",
      label: "own",
      status: "CONNECTED",
      egressEnforcement: true,
      daemonLeasePolicy: true,
    },
  });
  await db.inspect.sandboxPoolMember.create({
    data: {
      userId: f.id,
      hostOwnerId: grantee,
      poolId: f.pool.id,
      sandboxHostId: own.id,
      shareId: share.id,
      contributeWitness: true,
      ownHostsOnlyWitness: false,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: grantee,
      sandboxHostId: own.id,
      slug: "target",
      label: "Target",
      incusFingerprint: f.revision.incusFingerprint,
    },
  });
  const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
    where: { revisionId: revision.id, hostId: own.id },
  });
  const { id: _id, ...copy } = availability;
  for (const host of f.hosts)
    await db.inspect.sandboxTemplateAvailability.create({
      data: { ...copy, hostId: host.id, hostOwnerId: f.id },
    });
  const buildId = await seedBuild(grantee, revision.templateId, revision.id, f.pool.id);
  const principal = { kind: "session" as const, ownerId: grantee };
  const foreign = [f.host.id, f.other.id];
  for (const id of [own.id, ...foreign]) await setFlags(id, {});
  /** Everything a foreign build needs, on both foreign hosts. */
  const foreignReady = async () => {
    await db.inspect.accountImagePolicy.upsert({
      where: { userId: grantee },
      create: { userId: grantee, allowForeignBuilds: true },
      update: { allowForeignBuilds: true },
    });
    for (const id of foreign)
      await setFlags(id, { build: true, acceptForeignBuilds: true, acceptForeign: true });
  };
  const place = (options: { buildId?: string | null; timeoutMs?: number } = { buildId }) =>
    db.prisma.$transaction(async (tx) => {
      await lockPlacementPrincipals(tx, [grantee, f.id]);
      const placed = await resolvePlacement(
        tx,
        principal,
        {
          poolId: f.pool.id,
          template: `revision/${revision.id}`,
          timeoutMs: options.timeoutMs ?? 3_600_000,
        },
        { buildId: options.buildId },
      );
      return placed.hostId;
    });
  return { f, grantee, own, foreign, revision, buildId, principal, foreignReady, place };
}

describe("builder stage", () => {
  it("places a build only on a builder; without one the refusal hints why (booleans, never counts)", async () => {
    const s = await sharedPool();
    // A plain create still uses every host: the stage is inert.
    expect([s.own.id, ...s.foreign]).toContain(await s.place({ buildId: null }));
    await expect(s.place()).rejects.toMatchObject({
      data: {
        code: "template.build_no_builder",
        skipped: { builder: true, capture_policy: false, lease: false },
      },
    });
    await setFlags(s.own.id, { build: true });
    expect(await s.place()).toBe(s.own.id);
  });

  it("a foreign builder needs the opt-in, S3, an ANY_NODE target and both node acceptances (r1 M-4)", async () => {
    const s = await sharedPool();
    await s.foreignReady();
    expect(s.foreign).toContain(await s.place());

    // Hints only: the refusal says some host was skipped for a reason, never
    // how many (other owners' pool members stay undisclosed).
    const refused = () =>
      expect(s.place()).rejects.toMatchObject({
        data: {
          code: "template.build_no_builder",
          skipped: { builder: true, capture_policy: true, lease: false },
        },
      });
    image.mode = "peer";
    await refused();
    image.mode = "s3";

    await db.inspect.sandboxTemplate.update({
      where: { id: s.revision.templateId },
      data: { imagePlacement: "OWNED_NODES_ONLY" },
    });
    await refused();
    // Inherit from the account default, which is own-only too.
    await db.inspect.sandboxTemplate.update({
      where: { id: s.revision.templateId },
      data: { imagePlacement: "INHERIT" },
    });
    await db.inspect.accountImagePolicy.update({
      where: { userId: s.grantee },
      data: { imagePlacement: "OWNED_NODES_ONLY" },
    });
    await refused();
    await db.inspect.accountImagePolicy.update({
      where: { userId: s.grantee },
      data: { imagePlacement: "ANY_NODE", allowForeignBuilds: false },
    });
    await refused();
    await db.inspect.accountImagePolicy.update({
      where: { userId: s.grantee },
      data: { allowForeignBuilds: true },
    });
    // The node takes foreign builds but not foreign images: capture policy.
    await setFlags(s.foreign[0]!, { build: true, acceptForeignBuilds: true });
    // The node builds only for its owner: not a builder for this requester.
    await setFlags(s.foreign[1]!, { build: true, acceptForeign: true });
    await refused();
    await setFlags(s.foreign[1]!, { build: true, acceptForeign: true, acceptForeignBuilds: true });
    expect(await s.place()).toBe(s.foreign[1]);
  });

  it("an own builder ranks first, even when more loaded than foreign builders", async () => {
    const s = await sharedPool();
    await s.foreignReady();
    await setFlags(s.own.id, { build: true });
    await db.inspect.sandboxHost.update({
      where: { id: s.own.id },
      data: { memoryReservedMiB: 40960 },
    });
    expect(await s.place()).toBe(s.own.id);
  });

  it("a builder whose lease ceiling is below the build lease is skipped as `lease`", async () => {
    const s = await sharedPool();
    await setFlags(s.own.id, { build: true });
    await db.inspect.sandboxHost.update({
      where: { id: s.own.id },
      data: { daemonMaxLeaseMs: 600_000 },
    });
    await expect(s.place({ buildId: s.buildId, timeoutMs: 3_600_000 })).rejects.toMatchObject({
      data: {
        code: "template.build_no_builder",
        skipped: { builder: true, capture_policy: false, lease: true },
      },
    });
    expect(await s.place({ buildId: s.buildId, timeoutMs: 300_000 })).toBe(s.own.id);
  });

  it("a direct build target must be an own builder within its lease ceiling", async () => {
    const s = await sharedPool();
    const direct = (timeoutMs = 3_600_000) =>
      db.prisma.$transaction(async (tx) =>
        resolvePlacement(
          tx,
          s.principal,
          { sandboxHostId: s.own.id, template: `revision/${s.revision.id}`, timeoutMs },
          { buildId: s.buildId },
        ),
      );
    await expect(direct()).rejects.toMatchObject({
      data: {
        code: "template.build_no_builder",
        skipped: { builder: true, capture_policy: false, lease: false },
      },
    });
    await setFlags(s.own.id, { build: true });
    await db.inspect.sandboxHost.update({
      where: { id: s.own.id },
      data: { daemonMaxLeaseMs: 600_000 },
    });
    await expect(direct()).rejects.toMatchObject({
      data: {
        code: "template.build_no_builder",
        skipped: { builder: false, capture_policy: false, lease: true },
      },
    });
    expect((await direct(300_000)).hostId).toBe(s.own.id);
  });

  it("refuses a build id the requester does not own with the typed authority code", async () => {
    const s = await sharedPool();
    await setFlags(s.own.id, { build: true });
    const other = await seedBuild(s.f.id, s.f.revision.templateId, s.f.revision.id, s.f.pool.id);
    await expect(s.place({ buildId: other })).rejects.toMatchObject({
      code: "FORBIDDEN",
      data: { code: "build.authority_lost" },
    });
  });

  it("reads allowForeignBuilds under the owner placement lock: a concurrent opt-in orders before the placement", async () => {
    const s = await sharedPool();
    await s.foreignReady();
    await db.inspect.accountImagePolicy.update({
      where: { userId: s.grantee },
      data: { allowForeignBuilds: false },
    });
    // The settings writer's shape: owner placement, then the policy row.
    const gate = db.pauseAt("toggle", { before: "$transaction.commit" });
    const toggled = db.run("toggle", () =>
      db.prisma.$transaction(async (tx) => {
        await lockOwnerPlacement(tx, s.grantee);
        await tx.accountImagePolicy.update({
          where: { userId: s.grantee },
          data: { allowForeignBuilds: true },
        });
      }),
    );
    await gate.waitReached();
    const placing = db.run("place", () => s.place());
    expect((await db.waitUntilBlocked("place", { by: "toggle" })).query).toContain(
      "pg_advisory_xact_lock",
    );
    gate.release();
    await toggled;
    expect(s.foreign).toContain(await placing);
  });
});

describe("capacity queue build head (r2 N11)", () => {
  /** A strict (bypasses spent) head on a full pool of one builder and one non-builder. */
  async function strictHead(build: boolean) {
    const f = await poolFixture(db);
    await setFlags(f.host.id, { build: true });
    await setFlags(f.other.id, {});
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: f.hosts.map((h) => h.id) } },
      data: { memoryReservedMiB: 65536 },
    });
    const queued = await createSandbox(f.owner, {
      ...f.input,
      idempotencyKey: randomUUID(),
      waitForCapacityMs: 3_600_000,
    });
    await db.inspect.sandboxCapacityWait.update({
      where: { sandboxId: queued.id },
      data: { bypassCount: HEAD_BYPASS_LIMIT, lastBlocker: "ram" },
    });
    if (build) {
      const buildId = await seedBuild(f.id, f.revision.templateId, f.revision.id, f.pool.id);
      await db.inspect.sandbox.update({
        where: { id: queued.id },
        data: { purpose: "TEMPLATE_BUILD", buildId },
      });
    }
    // Capacity frees (no pinned lease holds it): the head may use either host again.
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: f.hosts.map((h) => h.id) } },
      data: { memoryReservedMiB: 0 },
    });
    return f;
  }
  const reserved = (poolId: string) =>
    db.prisma.$transaction((tx) => reservedHostIds(tx, poolId, null));

  it("a workload head reserves every host it could use", async () => {
    const f = await strictHead(false);
    expect((await reserved(f.pool.id)).sort()).toEqual(f.hosts.map((h) => h.id).sort());
  });

  it("a build head never reserves a non-builder host", async () => {
    const f = await strictHead(true);
    expect(await reserved(f.pool.id)).not.toContain(f.other.id);
  });

  // Needs B5a: the head's authority resolves through `resolveStoredPrincipal`,
  // which yields the build principal (Sandbox.buildId first) only with B5a.
  it("a build head reserves exactly its builder hosts", async () => {
    const f = await strictHead(true);
    expect(await reserved(f.pool.id)).toEqual([f.host.id]);
  });
});
