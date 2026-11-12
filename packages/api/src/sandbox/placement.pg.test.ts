import { digestContextSnapshot } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "pool-placement-fixture",
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
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";
import { getPoolCapacity } from "./capacity-view";
import {
  hostCapacityConflict,
  hostDrainingConflict,
  hostUnavailable,
  templateImageRejected,
  unsupportedCapability,
} from "./errors";
import { releaseLiveResourcesOnInventoryProof, releaseRootResources } from "./host-admission";
import { setHostDraining } from "./services/hosts";
import { deletePool, removePoolMember } from "./services/pools";
import { createSandbox, reconnectSandbox } from "./services/sandboxes";
import { poolFixture, poolKey } from "./testing/pool-fixtures";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function releaseFixtureHolds(f: Awaited<ReturnType<typeof poolFixture>>) {
  const rows = await db.inspect.sandbox.findMany({
    where: { userId: f.id, liveResourcesHeld: true },
    take: 10,
    select: { id: true, sandboxHostId: true },
  });
  for (const row of rows)
    await db.prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.id);
      await releaseLiveResourcesOnInventoryProof(tx, {
        hostId: row.sandboxHostId!,
        ownerId: f.id,
        sandboxId: row.id,
      });
      await releaseRootResources(tx, {
        hostId: row.sandboxHostId!,
        ownerId: f.id,
        sandboxId: row.id,
      });
    });
}

it("dominant share ranks hosts (memory, vCPU and disk), ties by memory share then host ID", async () => {
  const f = await poolFixture(db);
  const [low, high] = [f.host.id, f.other.id].sort();
  const place = async () =>
    (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId;
  // Tie: identical hosts fall back to the lowest host ID.
  expect(await place()).toBe(low);
  await releaseFixtureHolds(f);
  // Memory-dominant: `low` is half full, `high` is a third full on vCPU.
  await db.inspect.sandboxHost.update({
    where: { id: low! },
    data: { memoryReservedMiB: 32768, vcpuReserved: 0, liveCount: 0, rootCount: 0 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: high! },
    data: { memoryReservedMiB: 0, vcpuReserved: 22, liveCount: 0, rootCount: 0 },
  });
  expect(await place()).toBe(high);
  await releaseFixtureHolds(f);
  // vCPU-dominant: `high` now exceeds `low` on its dominant (vCPU) share.
  await db.inspect.sandboxHost.update({ where: { id: high! }, data: { vcpuReserved: 40 } });
  expect(await place()).toBe(low);
  await releaseFixtureHolds(f);
  // Disk-dominant: the storage pool the root is charged to decides.
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { memoryReservedMiB: 0, vcpuReserved: 0, liveCount: 0, rootCount: 0 },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: low! },
    data: { diskReservedGiB: 6000 },
  });
  expect(await place()).toBe(high);
  await releaseFixtureHolds(f);
  // Equal dominant share, different memory share: the lower memory share wins.
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { userId: f.id },
    data: { diskReservedGiB: 0 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: low! },
    data: { memoryReservedMiB: 16384, vcpuReserved: 32 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: high! },
    data: { memoryReservedMiB: 0, vcpuReserved: 32 },
  });
  expect(await place()).toBe(high);
});
it("own hosts rank first when preferOwnHosts is on, spread by dominant share when off, and fall back when the own host is full", async () => {
  const f = await poolFixture(db);
  const grantee = randomUUID();
  await db.inspect.user.create({
    data: {
      id: grantee,
      name: "Grantee",
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
      slug: "grantee",
      label: "Grantee",
      incusFingerprint: f.revision.incusFingerprint,
    },
  });
  const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
    where: { revisionId: revision.id, hostId: own.id },
  });
  const { id: _availabilityId, ...copy } = availability;
  for (const host of f.hosts)
    await db.inspect.sandboxTemplateAvailability.create({
      data: { ...copy, hostId: host.id, hostOwnerId: f.id },
    });
  // The own host is the most loaded, so dominant share alone avoids it.
  await db.inspect.sandboxHost.update({
    where: { id: own.id },
    data: { memoryReservedMiB: 40960 },
  });
  const principal = { kind: "session" as const, ownerId: grantee };
  const place = async () =>
    (
      await db.inspect.sandbox.findUniqueOrThrow({
        where: {
          id: (
            await createSandbox(principal, {
              poolId: f.pool.id,
              template: `revision/${revision.id}`,
              idempotencyKey: randomUUID(),
            })
          ).id,
        },
      })
    ).sandboxHostId;
  expect(await place()).toBe(own.id);
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { preferOwnHosts: false },
  });
  expect([f.host.id, f.other.id]).toContain(await place());
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { preferOwnHosts: true },
  });
  // The own host lacks RAM: the preference is a tier, never a filter.
  await db.inspect.sandboxHost.update({
    where: { id: own.id },
    data: { memoryReservedMiB: 65536 },
  });
  expect([f.host.id, f.other.id]).toContain(await place());
});
it("template only on full hosts while another visible host is empty: pool_full with skipped template_unavailable; nowhere: template_unavailable; hidden hosts never count", async () => {
  const f = await poolFixture(db);
  const bare = await seedLaunchHost(db.inspect, {
    data: {
      userId: f.id,
      slug: "bare",
      label: "bare",
      status: "CONNECTED",
      egressEnforcement: true,
      daemonLeasePolicy: true,
    },
  });
  await db.inspect.sandboxPoolMember.create({
    data: { userId: f.id, hostOwnerId: f.id, poolId: f.pool.id, sandboxHostId: bare.id },
  });
  await db.inspect.sandboxHost.updateMany({
    where: { id: { in: [f.host.id, f.other.id] } },
    data: { memoryReservedMiB: 65536 },
  });
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    data: {
      code: "sandbox.pool_full",
      reason: "ram",
      skipped: ["template_unavailable"],
      retryable: true,
    },
  });
  // A key whose host allowlist hides the bare host sees no skipped hint.
  const key = await poolKey(db, f);
  const hidden = await createSandbox(key.principal, {
    ...f.input,
    idempotencyKey: randomUUID(),
  }).catch((error: unknown) => error);
  expect(hidden).toMatchObject({ data: { code: "sandbox.pool_full", reason: "ram" } });
  expect((hidden as { data: Record<string, unknown> }).data.skipped).toBeUndefined();
  await db.inspect.sandboxTemplateAvailability.deleteMany({
    where: { revisionId: f.revision.id },
  });
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({ data: { code: "sandbox.template_unavailable" } });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});
it("a revision with a start command places only on templateStartup hosts: no such host is pool_no_compatible_host; full ones carry skipped template_startup; a direct host without it is UNSUPPORTED_CAPABILITY", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { startCmd: "python3 -m http.server 8080" },
  });
  // No member admitted `templateStartup`: static, never a waitable refusal.
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    data: { code: "sandbox.pool_no_compatible_host", retryable: false },
  });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { daemonFeatures: { egressPolicy: true, terminal: true, templateStartup: true } },
  });
  // Even the less loaded host without the capability is never chosen.
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { memoryReservedMiB: 40960 },
  });
  expect(
    (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId,
  ).toBe(f.other.id);
  await releaseFixtureHolds(f);
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { memoryReservedMiB: 65536 },
  });
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({
    data: { code: "sandbox.pool_full", reason: "ram", skipped: ["template_startup"] },
  });
  // The capacity view composes the same stage: the host fits nothing.
  const view = await getPoolCapacity(f.owner, { id: f.pool.id, template: "base" });
  expect(view.fits).toBe(0);
  expect(view.hosts.find((h) => h.id === f.host.id)).toMatchObject({
    fits: 0,
    excludedBy: "template_startup",
    schedulable: false,
  });
  // A direct target is checked under H on the admitted features.
  await expect(
    createSandbox(f.owner, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST", data: { code: "UNSUPPORTED_CAPABILITY" } });
  // Without a start command the stage admits every host again.
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { startCmd: null },
  });
  expect(
    (await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() })).sandboxHostId,
  ).toBe(f.host.id);
});
it("template known but not verified on any online host's current connection is template_image_missing", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId: f.revision.id },
    data: { verifiedConnectionEpoch: null, status: "MISSING" },
  });
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    data: { code: "sandbox.template_image_missing" },
  });
});
it("pool_placement_skips_draining_member", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 131072 },
  });
  await setHostDraining(f.owner, { id: f.host.id, draining: true });
  expect((await createSandbox(f.owner, f.input)).sandboxHostId).toBe(f.other.id);
});
it("pool_all_draining_is_pool_unavailable", async () => {
  const f = await poolFixture(db);
  for (const host of f.hosts) await setHostDraining(f.owner, { id: host.id, draining: true });
  // Draining is reversible host state (undrain below), not a disabled member.
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.pool_unavailable", retryable: true },
  });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});
it("undrain_restores_pool_eligibility without restarting or changing connection epoch", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { status: "DISCONNECTED" },
  });
  await setHostDraining(f.owner, { id: f.host.id, draining: true });
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    data: { code: "sandbox.pool_unavailable" },
  });
  await setHostDraining(f.owner, { id: f.host.id, draining: false });
  expect((await createSandbox(f.owner, f.input)).sandboxHostId).toBe(f.host.id);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).connectionEpoch,
  ).toBe(f.host.connectionEpoch);
});
it.each(["offline", "stale", "future", "inventory", "quarantine", "key-ack"] as const)(
  "pool online predicate skips %s",
  async (state) => {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.updateMany({
      where: { userId: f.id },
      data:
        state === "offline"
          ? { status: "DISCONNECTED" }
          : state === "stale"
            ? { lastHeartbeatAt: new Date(0) }
            : state === "future"
              ? { lastHeartbeatAt: new Date(Date.now() + 60000) }
              : state === "inventory"
                ? { inventoryAcknowledgedEpoch: null }
                : state === "quarantine"
                  ? { quarantinedAt: new Date() }
                  : { journalKeyAcknowledgedEpoch: null },
    });
    await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
      data: { code: "sandbox.pool_unavailable" },
    });
  },
);
it.each([
  "sandbox.create",
  "sandboxHost.updateMany",
  "sandboxExecutionConfig.create",
  "sandboxOperation.create",
  "sandboxPlacement.create",
  "outboxEvent.create",
  "sandbox.update",
])("pool rollback at %s leaves no rows/counters", async (step) => {
  const f = await poolFixture(db);
  const gate = db.pauseAt("allocate", { after: step });
  const outcome = db
    .run("allocate", () => createSandbox(f.owner, f.input))
    .then(
      () => null,
      (error: unknown) => error,
    );
  await gate.waitReached();
  gate.fail(new Error("Injected pool rollback"));
  expect(await outcome).not.toBeNull();
  for (const table of [
    db.inspect.sandbox,
    db.inspect.sandboxOperation,
    db.inspect.sandboxExecutionConfig,
    db.inspect.sandboxPlacement,
    db.inspect.outboxEvent,
  ]) {
    expect(await table.count({ where: { userId: f.id } })).toBe(0);
  }
  expect(
    (
      await db.inspect.sandboxHost.aggregate({
        where: { userId: f.id },
        _sum: { liveCount: true },
      })
    )._sum.liveCount,
  ).toBe(0);
});
it("same-key replay retains placement/deadline after time, tag, member and pool changes", async () => {
  const f = await poolFixture(db);
  const first = await createSandbox(f.owner, f.input);
  const member = { poolId: f.pool.id, sandboxHostId: first.sandboxHostId! };
  await removePoolMember(f.owner, member);
  await deletePool(f.owner, { id: f.pool.id });
  await db.inspect.sandboxTemplateTag.deleteMany({ where: { templateId: f.revision.templateId } });
  const replay = await createSandbox(f.owner, f.input, () => new Date(Date.now() + 3_600_000));
  expect(replay.id).toBe(first.id);
  expect(replay.leaseExpiresAt).toEqual(first.leaseExpiresAt);
  expect(await db.inspect.sandboxPlacement.count({ where: { userId: f.id } })).toBe(1);
  await expect(createSandbox(f.owner, { ...f.input, timeoutMs: 1000 })).rejects.toMatchObject({
    data: { code: "sandbox.idempotency_conflict" },
  });
});
it.each(["pool", "direct", "cold"] as const)(
  "last-slot overlapping pools A/B versus %s serializes on placement advisory (pool/direct) or G before H (cold) and reserves once",
  async (opponent) => {
    const f = await poolFixture(db);
    await db.inspect.sandboxPoolMember.deleteMany({ where: { sandboxHostId: f.other.id } });
    const poolB = await db.inspect.sandboxPool.create({
      data: {
        userId: f.id,
        slug: "b",
        label: "B",
        Members: { create: { sandboxHostId: f.host.id, hostOwnerId: f.id } },
      },
    });
    let stoppedId: string | undefined;
    if (opponent === "cold") {
      const stopped = await createSandbox(f.owner, f.input);
      stoppedId = stopped.id;
      await db.inspect.sandboxOperation.updateMany({
        where: { sandboxId: stopped.id },
        data: { state: "SUCCEEDED" },
      });
      await db.inspect.outboxEvent.updateMany({
        where: { aggregateId: stopped.id },
        data: { processedAt: new Date() },
      });
      await db.inspect.sandbox.update({
        where: { id: stopped.id },
        data: { state: "STOPPED", liveResourcesHeld: false },
      });
    }
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        liveCount: 0,
        memoryReservedMiB: 0,
        vcpuReserved: 0,
        daemonMemoryBudgetMiB: 1536,
      },
    });
    // Cold takes no owner placement advisory. Hold it at H to make create
    // demonstrably contend at the capacity row rather than infer from outcomes.
    const holderGate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const holder = db.run("holder", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
        await tx.sandboxHost.update({
          where: { id: f.host.id },
          data: { lastHeartbeatAt: new Date() },
        });
      }),
    );
    await holderGate.waitReached();
    const firstGate = db.pauseAt("first", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const first = db.run("first", () =>
      createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
    );
    const firstOutcome = first.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    const blocked = await db.waitUntilBlocked("first", { by: "holder" });
    expect(blocked.query).toContain("sandbox_host");
    holderGate.release();
    await holder;
    await firstGate.waitReached();
    const second = db.run("second", () =>
      opponent === "cold"
        ? reconnectSandbox(f.owner, { id: stoppedId!, mode: "cold", idempotencyKey: randomUUID() })
        : createSandbox(
            f.owner,
            opponent === "direct"
              ? { template: "base", sandboxHostId: f.host.id, idempotencyKey: randomUUID() }
              : { ...f.input, poolId: poolB.id, idempotencyKey: randomUUID() },
          ),
    );
    const secondOutcome = second.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    const secondBlocked = await db.waitUntilBlocked("second", { by: "first" });
    expect(secondBlocked.query).toMatch(
      opponent === "cold" ? /sandbox_pool/ : /pg_advisory_xact_lock/,
    );
    firstGate.release();
    expect(await firstOutcome).toHaveProperty("value");
    expect(await secondOutcome).toHaveProperty("error");
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(1);
    expect(
      await db.inspect.sandbox.count({ where: { userId: f.id, liveResourcesHeld: true } }),
    ).toBe(1);
  },
);

it.each(["same", "missing-pool", "different-key"] as const)(
  "real P2002 pool recovery %s fences concurrent graph withdrawal, then replays stored allocation",
  async (mode) => {
    const f = await poolFixture(db);
    const input = { diskGiB: 32, ...f.input, cpuCount: 3, memoryMiB: 2048 };
    const { poolKey } = await import("./testing/pool-fixtures");
    const key = await poolKey(db, f);
    const otherKey = await poolKey(db, f);
    const original = await createSandbox(key.principal, input);
    const prior = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: original.id },
    });
    // Free the unique key so the losing create reaches its tentative O insert.
    await db.inspect.sandboxOperation.update({
      where: { id: prior.id },
      data: { idempotencyKey: randomUUID() },
    });
    const parked = db.pauseAt("loser", { before: "sandboxOperation.create" });
    const loser = db.run("loser", () =>
      createSandbox(key.principal, input, () => new Date(Date.now() + 3_600_000)),
    );
    const outcome = loser.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    await parked.waitReached();
    const winner = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        ...prior,
        id: randomUUID(),
        authorizingKeyId: mode === "different-key" ? otherKey.key.id : key.key.id,
      },
    });
    const recovery = db.pauseAt("loser", { before: /^sql:SELECT id FROM "user".*FOR SHARE$/ });
    parked.release();
    await recovery.waitReached();
    // Losing S/config/placement/reservation were rolled back, not leaked.
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
    expect(await db.inspect.sandboxPlacement.count({ where: { userId: f.id } })).toBe(1);
    expect(
      (
        await db.inspect.sandboxHost.aggregate({
          where: { userId: f.id },
          _sum: { liveCount: true },
        })
      )._sum.liveCount,
    ).toBe(1);
    expect(
      (
        await db.inspect.sandboxHost.aggregate({
          where: { userId: f.id },
          _sum: { memoryReservedMiB: true },
        })
      )._sum.memoryReservedMiB,
    ).toBe(vmLiveMemoryChargeMiB(2048));
    await deletePool(f.owner, { id: f.pool.id });
    await db.inspect.sandboxTemplateTag.deleteMany({
      where: { templateId: f.revision.templateId },
    });
    await db.inspect.sandboxPoolMember.updateMany({
      where: { poolId: f.pool.id },
      data: { removedAt: new Date(), enabled: false },
    });
    if (mode === "missing-pool")
      await db.inspect.sdkKeyPoolAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    recovery.release();
    // deletePool now invalidates the in-flight owner ticket. A fresh request
    // still recovers the immutable receipt without a new placement or hold.
    expect(await outcome).toMatchObject({ error: { code: "FORBIDDEN" } });
    if (mode === "same" || mode === "missing-pool")
      expect(await createSandbox(key.principal, input)).toMatchObject({
        diskGiB: 32,
        id: original.id,
        leaseExpiresAt: original.leaseExpiresAt,
        cpuCount: 3,
        memoryMiB: 2048,
      });
    else
      await expect(createSandbox(key.principal, input)).rejects.toMatchObject({
        code: "CONFLICT",
        data: { code: "sandbox.idempotency_conflict" },
      });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: winner.id } }))
        .requestBodyHash,
    ).toBe(prior.requestBodyHash);
  },
);

it.each(["drain", "cap", "epoch"] as const)(
  "allocation rechecks %s after waiting on H and retries from a fresh transaction",
  async (change) => {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { daemonMemoryBudgetMiB: 131072 },
    });
    const gate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const holder = db.run("holder", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
        await tx.sandboxHost.update({
          where: { id: f.host.id },
          data:
            change === "drain"
              ? { draining: true }
              : change === "cap"
                ? { daemonMemoryBudgetMiB: 512 }
                : { connectionEpoch: f.host.connectionEpoch + 1 },
        });
      }),
    );
    await gate.waitReached();
    const allocation = db.run("allocate", () => createSandbox(f.owner, f.input));
    const result = allocation.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    expect((await db.waitUntilBlocked("allocate", { by: "holder" })).query).toContain(
      "sandbox_host",
    );
    gate.release();
    await holder;
    expect(await result).toMatchObject({ value: { sandboxHostId: f.other.id } });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
  },
);
it("SDK revoke while allocation holds K waits; commit stays accepted and is not a pool refusal", async () => {
  const f = await poolFixture(db);
  const { poolKey } = await import("./testing/pool-fixtures");
  const { revokeSdkKey } = await import("./services/sdk-keys");
  const key = await poolKey(db, f);
  const gate = db.pauseAt("allocate", { after: "sandboxPlacement.create" });
  const allocation = db.run("allocate", () => createSandbox(key.principal, f.input));
  // The result guard can refuse disclosure after committed revocation; the
  // allocation itself remains durable and dispatch handles revocable authority.
  const result = allocation.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  await gate.waitReached();
  const revoke = db.run("revoke", () => revokeSdkKey(f.owner, { id: key.key.id }));
  const revoked = revoke.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  expect((await db.waitUntilBlocked("revoke", { by: "allocate" })).query).toContain("sdk_key");
  gate.release();
  await result;
  expect(await revoked).toHaveProperty("value");
  expect(await db.inspect.sandbox.count({ where: { userId: f.id, liveResourcesHeld: true } })).toBe(
    1,
  );
});

it("placement holds G before waiting on H; revision parents and S follow H, final suffix follows outbox", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 131072 },
  });
  const gate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(
      (tx) => tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`,
    ),
  );
  await gate.waitReached();
  const creator = db.run("allocate", () => createSandbox(f.owner, f.input));
  const result = creator.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  expect((await db.waitUntilBlocked("allocate", { by: "holder" })).query).toContain("sandbox_host");
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  await expect(
    db.inspect.$transaction(
      (tx) => tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ${f.pool.id} FOR UPDATE NOWAIT`,
    ),
  ).rejects.toMatchObject({
    code: "P2010",
    meta: expect.objectContaining({
      driverAdapterError: expect.objectContaining({
        cause: expect.objectContaining({ code: "55P03" }),
      }),
    }),
  });
  await db.inspect.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${f.revision.templateId} FOR UPDATE NOWAIT`;
    await tx.$queryRaw`SELECT id FROM sandbox_template_revision WHERE id = ${f.revision.id} FOR UPDATE NOWAIT`;
    await tx.$queryRaw`SELECT id FROM sandbox_pool_member WHERE "poolId" = ${f.pool.id} FOR UPDATE NOWAIT`;
  });
  const outbox = db.pauseAt("allocate", { after: "outboxEvent.create" });
  gate.release();
  await holder;
  await outbox.waitReached();
  // The transaction's own outbox is not committed, and the member has not
  // been locked before the availability/member suffix.
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
  await db.inspect.$transaction(
    (tx) =>
      tx.$queryRaw`SELECT id FROM sandbox_pool_member WHERE "poolId" = ${f.pool.id} FOR UPDATE NOWAIT`,
  );
  outbox.release();
  expect(await result).toHaveProperty("value");
  expect(await db.inspect.sandboxPlacement.count({ where: { userId: f.id } })).toBe(1);
});
it("pool placement samples the DB receipt clock after H despite an opposing application clock", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 131072 },
  });
  const gate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
      await tx.$executeRaw`UPDATE sandbox_host SET "lastHeartbeatAt" = clock_timestamp() WHERE id = ${f.host.id}`;
    }),
  );
  await gate.waitReached();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2000-01-01T00:00:00Z"));
  try {
    const creator = db.run("allocate", () => createSandbox(f.owner, f.input));
    const result = creator.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    const observed = await Promise.race([
      db.waitUntilBlocked("allocate", { by: "holder" }),
      result.then((finished) => ({ finished })),
    ]);
    expect(observed).toHaveProperty("query");
    gate.release();
    await holder;
    expect(await result).toMatchObject({ value: { sandboxHostId: f.host.id } });
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    expect(host.lastPlacedAt!.getTime()).toBeGreaterThanOrEqual(f.host.lastHeartbeatAt!.getTime());
    expect(host.lastPlacedAt!.getFullYear()).toBeGreaterThan(2000);
  } finally {
    gate.release();
    vi.useRealTimers();
    await holder;
  }
});

it("cold connect retains pooled host/member/revision/config after pool deletion and membership removal", async () => {
  const f = await poolFixture(db);
  const { poolKey } = await import("./testing/pool-fixtures");
  const key = await poolKey(db, f);
  const sandbox = await createSandbox(key.principal, f.input);
  const first = await db.inspect.sandboxPlacement.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: sandbox.id },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: sandbox.id },
    data: { processedAt: new Date() },
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  await db.inspect.sandboxHost.update({
    where: { id: sandbox.sandboxHostId! },
    data: {
      liveCount: 0,
      memoryReservedMiB: 0,
      vcpuReserved: 0,
      daemonMemoryBudgetMiB: 1536,
    },
  });
  await removePoolMember(f.owner, { poolId: f.pool.id, sandboxHostId: sandbox.sandboxHostId! });
  await deletePool(f.owner, { id: f.pool.id });
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId: f.revision.id },
    data: { status: "MISSING" },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: new Date() },
  });
  // §5a (W1): the creating key's pool grant went with the pool, so it lost
  // use; the owner's cold connect keeps every retained placement fact.
  await expect(
    reconnectSandbox(key.principal, { id: sandbox.id, mode: "cold", idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await reconnectSandbox(f.owner, {
    id: sandbox.id,
    mode: "cold",
    idempotencyKey: randomUUID(),
  });
  const current = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
  const next = await db.inspect.sandboxPlacement.findUniqueOrThrow({
    where: { id: current.currentPlacementId! },
  });
  expect(next).toMatchObject({
    kind: "POOL",
    generation: 2,
    originHostId: first.originHostId,
    originPoolId: first.originPoolId,
    originMemberId: first.originMemberId,
    templateRevisionId: first.templateRevisionId,
    configId: first.configId,
  });
  expect(current.sandboxHostId).toBe(sandbox.sandboxHostId);
  expect(current.liveResourcesHeld).toBe(true);
});

it("placement suffix locks availability before the member, after outbox writes", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 131072 },
  });
  const memberGate = db.pauseAt("member-holder", { after: /SELECT id FROM sandbox_pool_member/ });
  const holder = db.run("member-holder", () =>
    db.prisma.$transaction(
      (tx) =>
        tx.$queryRaw`SELECT id FROM sandbox_pool_member WHERE "poolId" = ${f.pool.id} AND "sandboxHostId" = ${f.host.id} FOR UPDATE`,
    ),
  );
  await memberGate.waitReached();
  const creator = db.run("allocate", () => createSandbox(f.owner, f.input));
  const result = creator.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  let probing: Promise<unknown> | undefined;
  try {
    expect((await db.waitUntilBlocked("allocate", { by: "member-holder" })).query).toContain(
      "sandbox_pool_member",
    );
    probing = db.run("availability-probe", () =>
      db.prisma.$transaction(
        (tx) =>
          tx.$queryRaw`SELECT id FROM sandbox_template_availability WHERE "hostId" = ${f.host.id} AND "revisionId" = ${f.revision.id} FOR UPDATE`,
      ),
    );
    const observed = await Promise.race([
      db.waitUntilBlocked("availability-probe", { by: "allocate" }),
      probing.then(() => ({ acquiredTooEarly: true })),
    ]);
    expect(observed).toHaveProperty("query");
    const pid = db.backendPid("allocate");
    const written = await db.inspect.$queryRaw<{ acquired: boolean }[]>`SELECT EXISTS (
      SELECT 1 FROM pg_locks WHERE pid = ${pid} AND relation = 'sandbox_dispatch_outbox'::regclass
        AND mode = 'RowExclusiveLock'
    ) AS acquired`;
    expect(written).toEqual([{ acquired: true }]);
  } finally {
    memberGate.release();
    await holder;
    await probing;
  }
  expect(await result).toHaveProperty("value");
});

it("cold reconnect wins last slot first; waiting pool create rechecks, rolls back, retries and reports pool_full", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxPoolMember.deleteMany({ where: { sandboxHostId: f.other.id } });
  const stopped = await createSandbox(f.owner, f.input);
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: stopped.id },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: stopped.id },
    data: { processedAt: new Date() },
  });
  await db.inspect.sandbox.update({
    where: { id: stopped.id },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      liveCount: 0,
      memoryReservedMiB: 0,
      vcpuReserved: 0,
      daemonMemoryBudgetMiB: 1536,
    },
  });
  const coldGate = db.pauseAt("cold", { after: "sandboxHost.updateMany" });
  const cold = db.run("cold", () =>
    reconnectSandbox(f.owner, { id: stopped.id, mode: "cold", idempotencyKey: randomUUID() }),
  );
  const coldOutcome = cold.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  await coldGate.waitReached();
  // Cold holds G through its live-resource acquisition and attribution
  // clearing. Pool create must wait at G before it can select or lock H.
  const create = db.run("pool", () =>
    createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() }),
  );
  const createOutcome = create.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  const blocked = await db.waitUntilBlocked("pool", { by: "cold" });
  expect(blocked.query).toMatch(/FROM sandbox_pool .*FOR UPDATE/);
  coldGate.release();
  expect(await coldOutcome).toHaveProperty("value");
  expect(await createOutcome).toMatchObject({
    error: { code: "CONFLICT", data: { code: "sandbox.pool_full" } },
  });
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  expect(host.liveCount).toBe(1);
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
  expect(await db.inspect.sandboxPlacement.count({ where: { userId: f.id } })).toBe(2);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id, processedAt: null } })).toBe(
    1,
  );
});

it.each([
  { phase: "direct", error: hostUnavailable() },
  { phase: "direct", error: hostDrainingConflict() },
  { phase: "direct", error: templateImageRejected("changed image") },
  { phase: "direct", error: unsupportedCapability("egress") },
  { phase: "reserve", error: hostCapacityConflict() },
  { phase: "reserve", error: hostUnavailable() },
  { phase: "reserve", error: hostDrainingConflict() },
])(
  "post-selection $phase $error.data.code rolls back and reselects without leaking a host refusal",
  async ({ phase, error }) => {
    const f = await poolFixture(db);
    const gate = db.pauseAt("recheck", {
      before:
        phase === "direct" ? "sandboxTemplateAvailability.findFirst" : "sandboxHost.updateMany",
    });
    const outcome = db.run("recheck", () => createSandbox(f.owner, f.input));
    const result = outcome.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    await gate.waitReached();
    gate.fail(error);
    expect(await result).toMatchObject({
      value: expect.objectContaining({ originPoolId: f.pool.id }),
    });
    for (const table of [
      db.inspect.sandbox,
      db.inspect.sandboxOperation,
      db.inspect.sandboxExecutionConfig,
      db.inspect.sandboxPlacement,
      db.inspect.outboxEvent,
    ])
      expect(await table.count({ where: { userId: f.id } })).toBe(1);
    expect(
      (
        await db.inspect.sandboxHost.aggregate({
          where: { userId: f.id },
          _sum: { liveCount: true },
        })
      )._sum.liveCount,
    ).toBe(1);
  },
);

it("pool compatibility requires boolean egress evidence, not a JSON string", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonFeatures: { egressPolicy: "true" } },
  });
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.pool_no_compatible_host" },
  });
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonFeatures: { egressPolicy: true } },
  });
  expect((await createSandbox(f.owner, f.input)).originPoolId).toBe(f.pool.id);
});
