import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedLaunchHost } from "./testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

import { lockPoolGraph } from "./pool-locks";
import { addPoolMember } from "./services/pools";
import { listPoolInvites, listPoolShares } from "./services/sharing";
import { requirePoolContribution, requirePoolUse, usableMemberSelect } from "./sharing-authority";

vi.mock("./budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture() {
  const a = randomUUID(),
    b = randomUUID(),
    c = randomUUID();
  for (const id of [a, b, c])
    await db.inspect.user.create({ data: { id, name: id, email: `${id}@example.test` } });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: a, slug: randomUUID(), label: "Pool" },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: b, slug: randomUUID(), label: "Private host" },
  });
  const share = await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: a, granteeUserId: b, canUse: true, canContribute: false },
  });
  return { a, b, c, pool, host, share };
}
it("party authorizers keep use/contribute independent, own-host consent and uniform missing/foreign errors", async () => {
  const f = await fixture();
  const principal = { kind: "session" as const, ownerId: f.b };
  expect((await requirePoolUse(db.prisma, principal, f.pool.id)).share?.id).toBe(f.share.id);
  await expect(requirePoolContribution(db.prisma, f.b, f.pool.id, f.host.id)).rejects.toMatchObject(
    { code: "NOT_FOUND" },
  );
  await db.inspect.share.update({
    where: { id: f.share.id },
    data: { canUse: false, canContribute: true },
  });
  await expect(requirePoolUse(db.prisma, principal, f.pool.id)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect((await requirePoolContribution(db.prisma, f.b, f.pool.id, f.host.id)).hostOwnerId).toBe(
    f.b,
  );
  await expect(requirePoolContribution(db.prisma, f.c, f.pool.id, f.host.id)).rejects.toMatchObject(
    { code: "NOT_FOUND" },
  );
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { ownHostsOnly: true } });
  await expect(requirePoolContribution(db.prisma, f.b, f.pool.id, f.host.id)).rejects.toMatchObject(
    { code: "NOT_FOUND" },
  );
  expect(usableMemberSelect).toEqual({ id: true, poolId: true });
});
it("owner-only paginated share/invite views do not expose token digests or widen shared discovery", async () => {
  const f = await fixture();
  const input = { poolId: f.pool.id, limit: 1 };
  await db.inspect.shareInvite.create({
    data: {
      poolId: f.pool.id,
      ownerUserId: f.a,
      email: "target@example.test",
      pendingKey: `${f.pool.id}:target@example.test`,
      tokenDigest: "b".repeat(64),
      expiresAt: new Date(Date.now() + 3600000),
    },
  });
  const page = await listPoolInvites({ kind: "session", ownerId: f.a }, input);
  expect(page.items).toHaveLength(1);
  expect(page.items[0]).not.toHaveProperty("tokenDigest");
  expect(page.items[0]).not.toHaveProperty("pendingKey");
  for (const ownerId of [f.b, f.c])
    for (const read of [listPoolInvites, listPoolShares])
      await expect(read({ kind: "session", ownerId }, input)).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
});
it("member writer takes exclusive G before H, so a competing graph lock waits without owning H", async () => {
  const f = await fixture();
  const local = await db.inspect.sandboxHost.create({
    data: { userId: f.a, slug: randomUUID(), label: "Local" },
  });
  const pause = db.pauseAt("writer", { after: /sql:SELECT id FROM sandbox_pool WHERE id = ANY/ });
  const writer = db.run("writer", () =>
    addPoolMember(
      { kind: "session", ownerId: f.a },
      { poolId: f.pool.id, sandboxHostId: local.id, enabled: true },
    ),
  );
  await pause.waitReached();
  const graph = db.run("graph", () =>
    db.prisma.$transaction((tx) => lockPoolGraph(tx, [f.pool.id])),
  );
  try {
    await db.waitUntilBlocked("graph", { by: "writer" });
  } finally {
    pause.release();
  }
  await writer;
  await graph;
});

it("share sums use only current placements and retain disk across STOP/recreated Shares", async () => {
  const { seedTemplateRevision, seedSandboxInstance } = await import("./testing/resource-fixtures");
  const { shareUsage, shareUsageByCreator } = await import("./sharing-quota");
  const f = await fixture();
  const grouped = async () => {
    const usage = await shareUsageByCreator(db.prisma, f.pool.id, [f.a, f.b]);
    // A creator with no sandboxes in the pool charges zero; the grouped read
    // matches the per-creator ledger used by quota checks.
    expect(usage.get(f.a)).toEqual({ memoryMiB: 0n, vcpu: 0n, diskGiB: 0n });
    expect(usage.get(f.b)).toEqual(await shareUsage(db.prisma, f.pool.id, f.b));
    return usage.get(f.b);
  };
  const rev = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.b,
      slug: "quota",
      label: "Quota",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.b,
      hostOwnerId: f.b,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      templateId: rev.id,
      state: "READY",
      liveResourcesHeld: true,
      usagePoolId: f.pool.id,
    },
  });
  const placement = await db.inspect.sandboxPlacement.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { rootChargeGiB: 33, storagePoolId: null, diskReservationHeld: false },
  });
  // Retained-disk fixture needs a real composite host/storage identity.
  const storage = await db.inspect.sandboxHostStoragePool.create({
    data: {
      userId: f.b,
      sandboxHostId: f.host.id,
      name: "default",
      marker: "quota-marker",
      capacityGiB: 1000,
      capacitySource: "explicit",
      connectionEpoch: 1,
      observationSequence: 1,
      reportedAt: new Date(),
      health: "healthy",
    },
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: {
      storagePoolId: storage.id,
      storageMarker: storage.marker,
      storagePoolName: storage.name,
      diskReservationHeld: true,
    },
  });
  const charge = {
    memoryMiB: BigInt(placement.chargedMemoryMiB!),
    vcpu: BigInt(placement.chargedVcpu!),
    diskGiB: 33n,
  };
  expect(await shareUsage(db.prisma, f.pool.id, f.b)).toEqual(charge);
  expect(await grouped()).toEqual(charge);
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.a, granteeUserId: f.b },
  });
  expect(await shareUsage(db.prisma, f.pool.id, f.b)).toEqual(charge);
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  expect(await grouped()).toEqual({ memoryMiB: 0n, vcpu: 0n, diskGiB: 33n });
  expect(await shareUsage(db.prisma, f.pool.id, f.b)).toEqual({
    memoryMiB: 0n,
    vcpu: 0n,
    diskGiB: 33n,
  });
  expect(await shareUsage(db.prisma, f.pool.id, f.b, sandbox.id)).toEqual({
    memoryMiB: 0n,
    vcpu: 0n,
    diskGiB: 0n,
  });
  // Offload S10: a detached copy holding its root reservation keeps its share
  // attribution (by its own usagePoolId), even with the sandbox excluded; a
  // released hold charges nothing.
  const copy = await db.inspect.sandboxDiskCopy.create({
    data: {
      sandboxId: sandbox.id,
      userId: f.b,
      hostId: f.host.id,
      hostOwnerId: f.b,
      usagePoolId: f.pool.id,
      storagePoolId: storage.id,
      storageMarker: storage.marker,
      storagePoolName: storage.name,
      rootChargeGiB: 40,
      offloadSeq: 1,
      createKey: "create-key",
      baseFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  expect(await grouped()).toEqual({ memoryMiB: 0n, vcpu: 0n, diskGiB: 73n });
  expect((await shareUsage(db.prisma, f.pool.id, f.b, sandbox.id)).diskGiB).toBe(40n);
  await db.inspect.sandboxDiskCopy.update({
    where: { id: copy.id },
    data: { diskReservationHeld: false },
  });
  expect((await shareUsage(db.prisma, f.pool.id, f.b)).diskGiB).toBe(33n);
});

it("raw share writes refuse a reversed G acquisition and retry after the service prefix commits", async () => {
  const f = await fixture();
  const pause = db.pauseAt("prefix", { after: /sql:SELECT id FROM sandbox_pool WHERE id = ANY/ });
  const holder = db.run("prefix", () =>
    db.prisma.$transaction((tx) => lockPoolGraph(tx, [f.pool.id])),
  );
  await pause.waitReached();
  try {
    await expect(
      db.inspect.share.update({
        where: { id: f.share.id },
        data: { canUse: false, canContribute: true },
      }),
    ).rejects.toBeDefined();
  } finally {
    pause.release();
  }
  await holder;
  await db.inspect.share.update({
    where: { id: f.share.id },
    data: { canUse: false, canContribute: true },
  });
});

it.each(["impersonated", "revoked"] as const)(
  "all pool/host consent writes refuse a durable %s cookie",
  async (mode) => {
    const { createRouterClient } = await import("@orpc/server");
    const { sandboxPoolsRouter } = await import("../routers/sandbox-pools");
    const { sandboxHostsRouter } = await import("../routers/sandbox-hosts");
    type Context = import("../context").Context;
    const f = await fixture();
    const user = await db.inspect.user.update({
      where: { id: f.a },
      data: { emailVerified: true, twoFactorEnabled: true },
    });
    const cookie = await db.inspect.session.create({
      data: {
        userId: f.a,
        token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000),
        impersonatedBy: mode === "impersonated" ? f.c : null,
      },
    });
    if (mode === "revoked") await db.inspect.session.delete({ where: { id: cookie.id } });
    const context: Context = {
      session: { user, session: cookie } as NonNullable<Context["session"]>,
    };
    const pools = createRouterClient(sandboxPoolsRouter, { context }),
      hosts = createRouterClient(sandboxHostsRouter, { context });
    const calls = [
      () => pools.update({ id: f.pool.id, slug: "changed", label: "Changed" }),
      () => pools.delete({ id: f.pool.id }),
      () => pools.addMember({ poolId: f.pool.id, sandboxHostId: f.host.id, enabled: true }),
      () => pools.updateMember({ poolId: f.pool.id, sandboxHostId: f.host.id, enabled: true }),
      () => pools.removeMember({ poolId: f.pool.id, sandboxHostId: f.host.id }),
      () => hosts.updateHost({ id: f.host.id, label: "Changed" }),
      () => hosts.deleteHost({ id: f.host.id }),
    ];
    for (const call of calls) await expect(call()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(await db.inspect.sandboxPool.findUnique({ where: { id: f.pool.id } })).toMatchObject({
      label: "Pool",
      deletedAt: null,
    });
    expect(await db.inspect.sandboxPoolMember.count({ where: { poolId: f.pool.id } })).toBe(0);
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
      label: "Private host",
      deletionRequestedAt: null,
    });
  },
);
