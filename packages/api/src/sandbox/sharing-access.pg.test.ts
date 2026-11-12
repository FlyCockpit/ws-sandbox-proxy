import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const mail = vi.hoisted(() => ({
  send: vi.fn(async () => {}),
  render: vi.fn((args: { sandboxId: string; kind: string; deadline: Date }) => ({
    subject: args.kind,
    html: args.sandboxId,
  })),
}));
vi.mock("@wssp/mailer", () => ({ sendEmail: mail.send, renderPoolAccessNotice: mail.render }));
vi.mock("./budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));

import {
  assertHostDeletable,
  initializeHostMemoryReservation,
  releaseLiveResourcesOnInventoryProof,
} from "./host-admission";
import { lockHostByEpoch } from "./relay-fence";
import { currentHostUsability, reconcileSandboxAccess, scanSandboxAccess } from "./sharing-access";
import { poolFixture } from "./testing/pool-fixtures";
import { seedSandboxInstance, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
const now = new Date("2030-01-01T00:00:00.000Z");
async function fixture(state: import("@wssp/db").SandboxState = "READY") {
  const f = await poolFixture(db);
  const creator = randomUUID();
  await db.inspect.user.create({
    data: { id: creator, name: "Creator", email: `${creator}@example.test` },
  });
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
      state,
      liveResourcesHeld: !["STOPPED", "DELETED", "HOST_LOST"].includes(state),
      leaseExpiresAt: new Date("2040-01-01"),
      leaseExpireAction: "STOP",
    },
  });
  await db.prisma.$transaction(async (tx) => {
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    await initializeHostMemoryReservation(tx, f.host.id, f.id);
  });
  return { ...f, creator, share, member, sandbox };
}
async function row(f: Awaited<ReturnType<typeof fixture>>) {
  return db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
}
async function reconcile(f: Awaited<ReturnType<typeof fixture>>, time = now) {
  return db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, f.sandbox.id, () => time));
}
it.each([
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPING",
  "STOPPED",
  "RECLAIMING",
  "UNREACHABLE",
  "RECOVERED",
  "HOST_LOST",
  "ERROR",
] as const)(
  "pins %s once, uses access STOP/KILL states independently of the lease",
  async (state) => {
    const f = await fixture(state);
    await db.inspect.share.delete({ where: { id: f.share.id } });
    await reconcile(f);
    const first = await row(f);
    expect(first.accessGraceUntil).toEqual(new Date(now.getTime() + 259200000));
    const stops = [
      "REQUESTED",
      "SCHEDULED",
      "PROVISIONING",
      "READY",
      "UNREACHABLE",
      "RECOVERED",
      "ERROR",
    ].includes(state);
    expect(first.state).toBe(stops ? "STOPPING" : state);
    await reconcile(f, new Date(now.getTime() + 1000));
    expect((await row(f)).accessGraceUntil).toEqual(first.accessGraceUntil);
    if (stops)
      await db.inspect.sandbox.update({
        where: { id: first.id },
        data: { state: "STOPPED", liveResourcesHeld: false },
      });
    await reconcile(f, first.accessGraceUntil!);
    const kill = await db.inspect.sandboxOperation.findFirst({
      where: { sandboxId: first.id, kind: "KILL_SANDBOX" },
      select: { idempotencyKey: true },
    });
    expect(Boolean(kill)).toBe(!["STOPPING", "RECLAIMING", "HOST_LOST"].includes(state));
    if (kill) expect(kill.idempotencyKey).toContain(":DESTROY:");
    expect((await row(f)).diskReservationHeld).toBe(true);
  },
);
it("ignores DELETED, and HOST_LOST without a host pins without taking H", async () => {
  const f = await fixture("DELETED");
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).toBeNull();
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: {
      state: "HOST_LOST",
      sandboxHostId: null,
      storagePoolId: null,
      storageMarker: null,
      storagePoolName: null,
      diskReservationHeld: false,
      rootChargeGiB: null,
    },
  });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).not.toBeNull();
});
it("takes no User/G/H/S locks on healthy rows; raw SQL loss needs no hint", async () => {
  const f = await fixture();
  await db.run("healthy", () => scanSandboxAccess(() => now));
  expect((await row(f)).accessGraceUntil).toBeNull();
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await scanSandboxAccess(() => now);
  expect((await row(f)).state).toBe("STOPPING");
  expect(await currentHostUsability(db.prisma, f.creator, f.sandbox.id)).toBe(false);
});
it("preserves the larger placement/current grace and cannot extend a deadline on repeat loss", async () => {
  const f = await fixture("STOPPED");
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { disconnectGraceSeconds: 0 },
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).toEqual(new Date(now.getTime() + 259200000));
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { disconnectGraceSeconds: 2592000 },
  });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).toEqual(new Date(now.getTime() + 259200000));
});
it("moves to the lowest fitting path and keeps overcommit only on a still-valid attribution", async () => {
  const f = await fixture();
  const pools = [];
  for (const maxMemoryMiB of [1, 16777216]) {
    const p = await db.inspect.sandboxPool.create({
      data: { userId: f.id, slug: randomUUID(), label: "Other" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { poolId: p.id, userId: f.id, hostOwnerId: f.id, sandboxHostId: f.host.id },
    });
    await db.inspect.share.create({
      data: { poolId: p.id, ownerUserId: f.id, granteeUserId: f.creator, maxMemoryMiB },
    });
    pools.push(p);
  }
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  expect((await row(f)).usagePoolId).toBe(pools[1]!.id);
  expect((await row(f)).state).toBe("READY");
  await db.inspect.share.update({
    where: { poolId_granteeUserId: { poolId: pools[1]!.id, granteeUserId: f.creator } },
    data: { maxMemoryMiB: 1 },
  });
  await reconcile(f);
  expect((await row(f)).state).toBe("READY");
});
it("host/pool-owner bans STOP without ban-created grace; an owner's ban also stops their own-host VMs without grace", async () => {
  const f = await fixture();
  await db.inspect.user.update({ where: { id: f.id }, data: { banned: true } });
  await reconcile(f);
  expect((await row(f)).state).toBe("STOPPING");
  expect((await row(f)).accessGraceUntil).toBeNull();
  const own = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.id,
      hostOwnerId: f.id,
      templateId: f.revision.id,
      originHostId: f.host.id,
      sandboxHostId: f.host.id,
      state: "READY",
      liveResourcesHeld: true,
    },
  });
  await scanSandboxAccess(() => now);
  // Review #2: the banned owner's own-host VM stops (disk kept), no deletion grace.
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: own.id } })).toMatchObject({
    state: "STOPPING",
    accessGraceUntil: null,
  });
});
it("rebuild and proof release count foreign creators exactly once; retained roots block host deletion", async () => {
  const f = await fixture();
  const before = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  expect(before.liveCount).toBe(1);
  expect(before.rootCount).toBe(1);
  await db.prisma.$transaction(async (tx) => {
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    const claim = { hostId: f.host.id, ownerId: f.creator, sandboxId: f.sandbox.id };
    expect(await releaseLiveResourcesOnInventoryProof(tx, claim)).toBe(true);
    expect(await releaseLiveResourcesOnInventoryProof(tx, claim)).toBe(false);
    await expect(assertHostDeletable(tx, f.host.id, f.id)).rejects.toMatchObject({
      code: "CONFLICT",
    });
  });
  const after = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  expect(after.liveCount).toBe(0);
  expect(after.memoryReservedMiB).toBe(0);
  expect(after.rootCount).toBe(1);
});
it("pins real loss when every remaining path is structurally valid but over cap", async () => {
  const f = await fixture();
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: randomUUID(), label: "Full" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: { userId: f.id, hostOwnerId: f.id, sandboxHostId: f.host.id, poolId: pool.id },
  });
  await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: f.id, granteeUserId: f.creator, maxMemoryMiB: 1 },
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  expect((await row(f)).state).toBe("STOPPING");
  expect((await row(f)).accessGraceUntil).not.toBeNull();
  expect((await row(f)).usagePoolId).toBe(f.pool.id);
});
it("restores a stopped disk before due destroy and cancels only a never-issued automatic delete", async () => {
  const f = await fixture("STOPPED");
  await db.inspect.sandboxPlacement.update({
    where: { id: f.sandbox.currentPlacementId! },
    data: { acceptedGraceSeconds: 0 },
  });
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { disconnectGraceSeconds: 0 },
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  expect((await row(f)).state).toBe("STOPPING");
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: f.creator },
  });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).toBeNull();
  expect((await row(f)).state).toBe("STOPPED");
  const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
  });
  expect(kill.state).toBe("CANCELLED");
  expect(
    await db.inspect.outboxEvent.count({ where: { aggregateId: f.sandbox.id, processedAt: null } }),
  ).toBe(0);
});
it("owned-host fallback clears both usage IDs before re-grant", async () => {
  const f = await fixture();
  const own = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.id,
      hostOwnerId: f.id,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      templateId: f.revision.id,
      usagePoolId: f.pool.id,
      usageMemberId: f.member.id,
      state: "READY",
      liveResourcesHeld: true,
    },
  });
  await db.prisma.$transaction((tx) => reconcileSandboxAccess(tx, own.id, () => now));
  const updated = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: own.id } });
  expect(updated.usagePoolId).toBeNull();
  expect(updated.usageMemberId).toBeNull();
  expect(updated.state).toBe("READY");
});
it("restore and loss serialize at G in both arrival orders without extending deadlines", async () => {
  const f = await fixture("STOPPED");
  await db.inspect.share.delete({ where: { id: f.share.id } });
  for (const restoreFirst of [true, false]) {
    const first = restoreFirst ? "restore" : "scan";
    const second = restoreFirst ? "scan" : "restore";
    const gate = db.pauseAt(first, { after: /sql:SELECT id FROM sandbox_pool WHERE/ });
    const restore = () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ${f.pool.id} FOR UPDATE`;
        await tx.share.upsert({
          where: { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.creator } },
          create: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: f.creator },
          update: { canUse: true },
        });
      });
    const scan = () => reconcile(f);
    const a = db.run(first, restoreFirst ? restore : scan);
    await gate.waitReached();
    const b = db.run(second, restoreFirst ? scan : restore);
    try {
      await db.waitUntilBlocked(second, { by: first });
    } finally {
      gate.release();
    }
    await Promise.all([a, b]);
    await reconcile(f);
    expect((await row(f)).accessGraceUntil).toBeNull();
    await db.inspect.share.delete({
      where: { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.creator } },
    });
  }
});
it("a healthy sweep completes while its User/G/H rows are locked by another transaction", async () => {
  const f = await fixture();
  const gate = db.pauseAt("holder", { after: /sql:SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.id} FOR UPDATE`;
      await tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ${f.pool.id} FOR UPDATE`;
      await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    }),
  );
  await gate.waitReached();
  try {
    expect(await scanSandboxAccess(() => now)).toBe(0);
  } finally {
    gate.release();
  }
  await holder;
});
it("path overflow refuses without pinning, then recovers after memberships are removed", async () => {
  const f = await fixture("STOPPED");
  const pools = [];
  for (let n = 0; n < 250; n++) {
    const p = await db.inspect.sandboxPool.create({
      data: { userId: f.id, slug: randomUUID(), label: "Path" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: f.id, hostOwnerId: f.id, poolId: p.id, sandboxHostId: f.host.id },
    });
    pools.push(p.id);
  }
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await expect(reconcile(f)).rejects.toMatchObject({
    code: "CONFLICT",
    message: expect.stringContaining("Remove pool memberships"),
  });
  expect((await row(f)).accessGraceUntil).toBeNull();
  const { deleteHost } = await import("./services/hosts");
  await expect(deleteHost(f.owner, { id: f.host.id })).rejects.toMatchObject({ code: "CONFLICT" });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }))
      .deletionRequestedAt,
  ).toBeNull();
  await db.inspect.sandboxPoolMember.updateMany({
    where: { poolId: pools[0]! },
    data: { removedAt: now },
  });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).not.toBeNull();
  expect(await deleteHost(f.owner, { id: f.host.id })).toEqual({ ok: true, pending: true });
});
it("refuses corrupt placement transport evidence instead of consuming foreign work", async () => {
  const f = await fixture();
  await db.inspect.sandboxPlacement.update({
    where: { id: f.sandbox.currentPlacementId! },
    data: { hostOwnerId: f.creator },
  });
  expect(await currentHostUsability(db.prisma, f.creator, f.sandbox.id)).toBe(false);
  await expect(reconcile(f)).rejects.toBeInstanceOf(
    (await import("./relay-fence")).RelayFenceRejected,
  );
  expect((await row(f)).accessGraceUntil).toBeNull();
});
it("host deletion takes G before H and withdraws every pool before waiting for retained-root cleanup", async () => {
  const f = await fixture();
  const { deleteHost } = await import("./services/hosts");
  const gate = db.pauseAt("host-holder", { after: /sql:SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const holder = db.run("host-holder", () =>
    db.prisma.$transaction((tx) => lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id)),
  );
  await gate.waitReached();
  const deletion = db.run("delete", () => deleteHost(f.owner, { id: f.host.id }));
  try {
    await db.waitUntilBlocked("delete", { by: "host-holder" });
    const graph = db.run("graph", () =>
      db.prisma.$transaction(
        (tx) => tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ${f.pool.id} FOR UPDATE`,
      ),
    );
    await db.waitUntilBlocked("graph", { by: "delete" });
    gate.release();
    expect(await deletion).toEqual({ ok: true, pending: true });
    await graph;
  } finally {
    gate.release();
    await holder;
  }
  expect(
    await db.inspect.sandboxPoolMember.count({
      where: { sandboxHostId: f.host.id, removedAt: null },
    }),
  ).toBe(0);
  await reconcile(f);
  expect((await row(f)).state).toBe("STOPPING");
  expect((await row(f)).diskReservationHeld).toBe(true);
});
it.each(["memory", "vcpu", "disk"] as const)(
  "requires a contributed destination to fit %s before restoring attribution",
  async (resource) => {
    const f = await fixture(resource === "disk" ? "STOPPED" : "READY");
    const poolOwner = randomUUID();
    await db.inspect.user.create({
      data: {
        id: poolOwner,
        name: "Pool owner",
        email: `${poolOwner}@example.test`,
        twoFactorEnabled: true,
        emailVerified: true,
      },
    });
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: poolOwner, slug: randomUUID(), label: "Contributed" },
    });
    const contribution = await db.inspect.share.create({
      data: {
        poolId: pool.id,
        ownerUserId: poolOwner,
        granteeUserId: f.id,
        canUse: false,
        canContribute: true,
      },
    });
    const use = await db.inspect.share.create({
      data: {
        poolId: pool.id,
        ownerUserId: poolOwner,
        granteeUserId: f.creator,
        canUse: true,
        canContribute: false,
        maxDiskGiB: resource === "disk" ? 1 : null,
      },
    });
    const member = await db.inspect.sandboxPoolMember.create({
      data: {
        poolId: pool.id,
        userId: poolOwner,
        hostOwnerId: f.id,
        sandboxHostId: f.host.id,
        shareId: contribution.id,
        contributeWitness: true,
        ownHostsOnlyWitness: false,
        memoryCapPercent: resource === "memory" ? 1 : null,
        vcpuCapPercent: resource === "vcpu" ? 1 : null,
      },
    });
    await db.inspect.share.delete({ where: { id: f.share.id } });
    await reconcile(f);
    expect((await row(f)).accessGraceUntil).not.toBeNull();
    expect((await row(f)).usagePoolId).toBe(f.pool.id);
    if (resource === "disk")
      await db.inspect.share.update({ where: { id: use.id }, data: { maxDiskGiB: 33 } });
    else
      await db.inspect.sandboxPoolMember.update({
        where: { id: member.id },
        data: resource === "memory" ? { memoryCapPercent: 10 } : { vcpuCapPercent: 10 },
      });
    await reconcile(f);
    expect((await row(f)).usagePoolId).toBe(pool.id);
    expect((await row(f)).accessGraceUntil).toBeNull();
    expect(await currentHostUsability(db.prisma, f.creator, f.sandbox.id)).toBe(true);
    expect((await row(f)).diskReservationHeld).toBe(true);
  },
);
it("ERROR without live resources pins without STOP and still destroys when access grace is due", async () => {
  const f = await fixture("ERROR");
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { liveResourcesHeld: false },
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  const pinned = await row(f);
  expect(pinned.state).toBe("ERROR");
  expect(pinned.accessGraceUntil).not.toBeNull();
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: pinned.id, kind: "STOP_SANDBOX" },
    }),
  ).toBe(0);
  await reconcile(f, pinned.accessGraceUntil!);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: pinned.id, kind: "KILL_SANDBOX" },
    }),
  ).toBe(1);
});
it("restoration after a pinned loss must fit recreated caps even when the member ID survives", async () => {
  const f = await fixture();
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await reconcile(f);
  const deadline = (await row(f)).accessGraceUntil;
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: f.creator, maxMemoryMiB: 1 },
  });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).toEqual(deadline);
  expect(await currentHostUsability(db.prisma, f.creator, f.sandbox.id)).toBe(false);
  await db.inspect.share.update({
    where: { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.creator } },
    data: { maxMemoryMiB: 16777216 },
  });
  await reconcile(f);
  expect((await row(f)).accessGraceUntil).toBeNull();
});
it("emits scoped graph hints only after commit, never on rollback", async () => {
  const f = await fixture();
  const { bindSharingAccessWake } = await import("./sharing-access");
  const { updatePool } = await import("./services/pools");
  const wake = vi.fn();
  bindSharingAccessWake(wake);
  try {
    await expect(updatePool(f.owner, { id: f.pool.id, label: "Updated" })).resolves.toMatchObject({
      label: "Updated",
    });
    expect(wake).toHaveBeenCalledExactlyOnceWith(f.pool.id);
    wake.mockClear();
    const other = await db.inspect.sandboxPool.create({
      data: { userId: f.id, slug: randomUUID(), label: "Reserved" },
    });
    await expect(updatePool(f.owner, { id: f.pool.id, slug: other.slug })).rejects.toMatchObject({
      code: "CONFLICT",
    });
    expect(wake).not.toHaveBeenCalled();
  } finally {
    bindSharingAccessWake(null);
  }
});
it("rolls back a failed suspect row and advances to the next row without a hint", async () => {
  const fixtures = [await fixture("STOPPED"), await fixture("STOPPED")].sort((a, b) =>
    a.sandbox.id.localeCompare(b.sandbox.id),
  );
  for (const f of fixtures) await db.inspect.share.delete({ where: { id: f.share.id } });
  const gate = db.pauseAt("scan-row-failure", { after: "sandbox.updateMany" });
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    const scan = db.run("scan-row-failure", () =>
      scanSandboxAccess(
        () => now,
        () => false,
        new Set(fixtures.map((f) => f.pool.id)),
      ),
    );
    await gate.waitReached();
    gate.fail(new Error("injected row failure"));
    await scan;
    expect((await row(fixtures[0]!)).accessGraceUntil).toBeNull();
    expect((await row(fixtures[1]!)).accessGraceUntil).not.toBeNull();
    expect(
      mail.render.mock.calls.some(([notice]) => notice.sandboxId === fixtures[0]!.sandbox.id),
    ).toBe(false);
    expect(
      mail.render.mock.calls.some(([notice]) => notice.sandboxId === fixtures[1]!.sandbox.id),
    ).toBe(true);
    expect(log).toHaveBeenCalledWith("[sharing-access] row deferred; periodic retry pending");
  } finally {
    gate.release();
    log.mockRestore();
  }
});
it("sends loss/restore notices after commit with the pinned deadline, once per transition", async () => {
  const f = await fixture("STOPPED");
  mail.send.mockClear();
  mail.render.mockClear();
  await db.inspect.share.delete({ where: { id: f.share.id } });
  const deadline = new Date(now.getTime() + 259200000);
  mail.send.mockImplementationOnce(async () => {
    // A separate client cannot see this pin until the scanner commits.
    expect((await row(f)).accessGraceUntil).toEqual(deadline);
  });
  const scan = () =>
    scanSandboxAccess(
      () => now,
      () => false,
      new Set([f.pool.id]),
    );
  await scan();
  expect(mail.render).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ sandboxId: f.sandbox.id, kind: "loss", deadline }),
  );
  expect(mail.send).toHaveBeenCalledOnce();
  await scan();
  expect(mail.send).toHaveBeenCalledOnce();
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: f.creator },
  });
  await scan();
  expect((await row(f)).accessGraceUntil).toBeNull();
  expect(mail.render).toHaveBeenLastCalledWith(
    expect.objectContaining({ sandboxId: f.sandbox.id, kind: "restore", deadline }),
  );
  expect(mail.send).toHaveBeenCalledTimes(2);
  await scan();
  expect(mail.send).toHaveBeenCalledTimes(2);
});
it("SMTP uncertainty preserves committed access loss without claiming delivery", async () => {
  const f = await fixture("STOPPED");
  await db.inspect.share.delete({ where: { id: f.share.id } });
  mail.send.mockRejectedValueOnce(new Error("fixture SMTP uncertainty"));
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await scanSandboxAccess(
      () => now,
      () => false,
      new Set([f.pool.id]),
    );
    expect((await row(f)).accessGraceUntil).not.toBeNull();
    expect(log).toHaveBeenCalledExactlyOnceWith("[sharing-access] notice delivery unconfirmed");
  } finally {
    log.mockRestore();
  }
});
it("pool-owner account deletion refuses without side effects until normal pool deletion is scanned", async () => {
  const f = await fixture();
  const poolOwner = randomUUID();
  await db.inspect.user.create({
    data: {
      id: poolOwner,
      name: "Pool owner",
      email: `${poolOwner}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const session = await db.inspect.session.create({
    data: {
      userId: poolOwner,
      token: `fixture-session-${randomUUID()}`,
      expiresAt: new Date("2040-01-01"),
    },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: poolOwner, slug: randomUUID(), label: "Shared work" },
  });
  const contribution = await db.inspect.share.create({
    data: {
      poolId: pool.id,
      ownerUserId: poolOwner,
      granteeUserId: f.id,
      canUse: false,
      canContribute: true,
    },
  });
  await db.inspect.share.create({
    data: {
      poolId: pool.id,
      ownerUserId: poolOwner,
      granteeUserId: f.creator,
      canUse: true,
      canContribute: false,
    },
  });
  const member = await db.inspect.sandboxPoolMember.create({
    data: {
      userId: poolOwner,
      hostOwnerId: f.id,
      poolId: pool.id,
      sandboxHostId: f.host.id,
      shareId: contribution.id,
      contributeWitness: true,
      ownHostsOnlyWitness: false,
    },
  });
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { usagePoolId: pool.id, usageMemberId: member.id },
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  const { requestAccountDeletion } = await import("@wssp/db/account-deletion");
  await expect(requestAccountDeletion(poolOwner)).rejects.toMatchObject({
    kinds: ["shared_pool_workloads"],
  });
  expect(
    (await db.inspect.user.findUniqueOrThrow({ where: { id: poolOwner } })).deletionRequestedAt,
  ).toBeNull();
  expect(await db.inspect.session.findUnique({ where: { id: session.id } })).not.toBeNull();
  expect(
    (await db.inspect.sandboxPool.findUniqueOrThrow({ where: { id: pool.id } })).deletedAt,
  ).toBeNull();
  const { deletePool } = await import("./services/pools");
  await deletePool({ kind: "session", ownerId: poolOwner }, { id: pool.id });
  await expect(requestAccountDeletion(poolOwner)).rejects.toMatchObject({
    kinds: ["shared_pool_workloads"],
  });
  await scanSandboxAccess(
    () => now,
    () => false,
    new Set([pool.id]),
  );
  expect((await row(f)).accessGraceUntil).not.toBeNull();
  expect(await requestAccountDeletion(poolOwner)).toBe(true);
  expect(await db.inspect.user.findUnique({ where: { id: poolOwner } })).toBeNull();
  expect((await row(f)).diskReservationHeld).toBe(true);
  expect((await row(f)).usagePoolId).toBe(pool.id);
});

it.each(["READY", "STOPPED"] as const)(
  "r1 250 active memberships plus withdrawn attribution pins grace and enforces %s cleanup",
  async (state) => {
    const f = await fixture(state);
    const { removePoolMember } = await import("./services/pools");
    await removePoolMember(f.owner, { poolId: f.pool.id, sandboxHostId: f.host.id });
    for (let n = 0; n < 250; n++) {
      const pool = await db.inspect.sandboxPool.create({
        data: {
          userId: f.id,
          slug: randomUUID(),
          label: "New path",
        },
      });
      await db.inspect.sandboxPoolMember.create({
        data: {
          userId: f.id,
          hostOwnerId: f.id,
          poolId: pool.id,
          sandboxHostId: f.host.id,
        },
      });
    }
    expect(
      await db.inspect.sandboxPoolMember.count({
        where: {
          sandboxHostId: f.host.id,
          removedAt: null,
        },
      }),
    ).toBe(250);
    await reconcile(f);
    const lost = await row(f);
    expect(lost.accessGraceUntil).toEqual(new Date(now.getTime() + 259200000));
    expect(lost.state).toBe(state === "READY" ? "STOPPING" : "STOPPED");
    expect(
      await db.inspect.sandboxOperation.count({
        where: {
          sandboxId: f.sandbox.id,
          kind: "STOP_SANDBOX",
        },
      }),
    ).toBe(state === "READY" ? 1 : 0);
    if (state === "READY")
      await db.inspect.sandbox.update({
        where: { id: f.sandbox.id },
        data: {
          state: "STOPPED",
          liveResourcesHeld: false,
        },
      });
    await reconcile(f, lost.accessGraceUntil!);
    expect(
      await db.inspect.sandboxOperation.count({
        where: {
          sandboxId: f.sandbox.id,
          kind: "KILL_SANDBOX",
        },
      }),
    ).toBe(1);
    expect((await row(f)).diskReservationHeld).toBe(true);
  },
);

it("terminal revalidation reattributes a lost path before closing, rejects a non-fitting fallback, and preserves session revocation", async () => {
  const { checkTerminalBinding } = await import("./terminal-tickets");
  const f = await fixture();
  const session = await db.inspect.session.create({
    data: {
      id: randomUUID(),
      token: randomUUID(),
      userId: f.creator,
      expiresAt: new Date("2040-01-01"),
    },
  });
  const binding = {
    userId: f.creator,
    sessionId: session.id,
    sandboxId: f.sandbox.id,
    hostId: f.host.id,
    generation: f.sandbox.generation,
  };
  const alternate = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: randomUUID(), label: "Alternate" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: { poolId: alternate.id, userId: f.id, hostOwnerId: f.id, sandboxHostId: f.host.id },
  });
  const share = await db.inspect.share.create({
    data: { poolId: alternate.id, ownerUserId: f.id, granteeUserId: f.creator },
  });
  expect(await checkTerminalBinding(binding)).toMatchObject({ ok: true });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  expect(await checkTerminalBinding(binding)).toMatchObject({ ok: true });
  expect(await row(f)).toMatchObject({
    usagePoolId: alternate.id,
    state: "READY",
    accessGraceUntil: null,
  });
  await db.inspect.session.delete({ where: { id: session.id } });
  expect(await checkTerminalBinding(binding)).toEqual({ ok: false, intent: "revoked" });
  await db.inspect.session.create({
    data: {
      id: session.id,
      token: randomUUID(),
      userId: f.creator,
      expiresAt: new Date("2040-01-01"),
    },
  });
  await db.inspect.share.delete({ where: { id: share.id } });
  // A remaining path whose cap cannot hold the guest must not preserve IO.
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: f.creator, maxMemoryMiB: 1 },
  });
  expect(await checkTerminalBinding(binding)).toEqual({ ok: false, intent: "pool_access_removed" });
  expect((await row(f)).state).toBe("STOPPING");
});

it.each([false, true])(
  "terminal revalidation re-reads after a scanner wins attribution (session revoked: %s)",
  async (revoke) => {
    const { checkTerminalBinding } = await import("./terminal-tickets");
    const f = await fixture();
    const session = await db.inspect.session.create({
      data: {
        id: randomUUID(),
        token: randomUUID(),
        userId: f.creator,
        expiresAt: new Date("2040-01-01"),
      },
    });
    const alternate = await db.inspect.sandboxPool.create({
      data: { userId: f.id, slug: randomUUID(), label: "Alternate" },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { poolId: alternate.id, userId: f.id, hostOwnerId: f.id, sandboxHostId: f.host.id },
    });
    await db.inspect.share.create({
      data: { poolId: alternate.id, ownerUserId: f.id, granteeUserId: f.creator },
    });
    await db.inspect.share.delete({ where: { id: f.share.id } });
    // Park after discovery, before G/H/S. The scanner commits the replacement
    // that will reject this check's old usagePoolId under the locked fence.
    const gate = db.pauseAt("terminal", { before: /sql:SELECT id FROM "user".*FOR SHARE/ });
    const check = db.run("terminal", () =>
      checkTerminalBinding({
        userId: f.creator,
        sessionId: session.id,
        sandboxId: f.sandbox.id,
        hostId: f.host.id,
        generation: f.sandbox.generation,
      }),
    );
    try {
      await gate.waitReached();
      await db.run("scanner", () => reconcile(f));
      expect((await row(f)).usagePoolId).toBe(alternate.id);
      if (revoke) await db.inspect.session.delete({ where: { id: session.id } });
    } finally {
      gate.release();
    }
    expect(await check).toMatchObject(revoke ? { ok: false, intent: "revoked" } : { ok: true });
    expect(await row(f)).toMatchObject({ state: "READY", accessGraceUntil: null });
  },
);

it("foreign placement capabilities follow live guest authority and both dashboard/native projections hide the host ID", async () => {
  const { getSandboxCapabilities } = await import("./services/capabilities");
  const { getSandboxView, listSandboxViews } = await import("./services/sandbox-views");
  const { getSandbox, listSandboxes } = await import("./services/sandboxes");
  const f = await fixture();
  const principal = { kind: "session" as const, ownerId: f.creator };
  const caps = await getSandboxCapabilities(principal, { id: f.sandbox.id });
  expect(caps.unavailableReason).toBeNull();
  expect(caps.features).toContain("files.list");
  expect(caps.features).toContain("commands.background");
  expect(JSON.stringify(caps)).not.toContain(f.host.id);
  for (const dto of [
    await getSandboxView(principal, { id: f.sandbox.id }),
    await getSandbox(principal, { id: f.sandbox.id }),
    ...(await listSandboxes(principal, { limit: 20 })).items,
    ...(await listSandboxViews(principal, { limit: 20 })).items,
  ]) {
    expect(dto.sandboxHostId).toBeNull();
    expect(JSON.stringify(dto)).not.toContain(f.host.id);
  }
  await expect(getSandboxCapabilities(f.owner, { id: f.sandbox.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await expect(getSandboxCapabilities(principal, { id: f.sandbox.id })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
});
