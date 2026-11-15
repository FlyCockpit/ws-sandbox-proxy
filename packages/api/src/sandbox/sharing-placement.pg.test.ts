import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "sharing-placement-test",
  },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("./budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { authenticateSdkKeySecret } from "../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../lib/service-scopes";
import { releaseLiveResourcesOnInventoryProof } from "./host-admission";
import { lockHostByEpoch } from "./relay-fence";
import { createSandbox, reconnectSandbox } from "./services/sandboxes";
import { createSdkKey } from "./services/sdk-keys";
import { requireOwnedSandboxPlacement } from "./sharing-authority";
import { poolFixture } from "./testing/pool-fixtures";
import { seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture() {
  const base = await poolFixture(db);
  await db.inspect.sandboxPoolMember.updateMany({
    where: { sandboxHostId: base.other.id },
    data: { enabled: false },
  });
  const creatorId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: creatorId,
      name: "Creator",
      email: `${creatorId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const share = await db.inspect.share.create({
    data: { poolId: base.pool.id, ownerUserId: base.id, granteeUserId: creatorId },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: creatorId,
      sandboxHostId: base.host.id,
      slug: "foreign",
      label: "Private revision",
      incusFingerprint: base.revision.incusFingerprint,
    },
  });
  const owner = { kind: "session" as const, ownerId: creatorId };
  const input = {
    poolId: base.pool.id,
    template: `revision/${revision.id}`,
    idempotencyKey: randomUUID(),
  };
  return { ...base, creatorId, share, revision, owner, input };
}
async function stop(f: Awaited<ReturnType<typeof fixture>>, id: string) {
  await db.prisma.$transaction(async (tx) => {
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    await releaseLiveResourcesOnInventoryProof(tx, {
      hostId: f.host.id,
      ownerId: f.creatorId,
      sandboxId: id,
    });
    await tx.sandbox.update({ where: { id }, data: { state: "STOPPED" } });
  });
}
it("foreign placement pins transport, usage and grace, while direct targeting and host custody grant no guest access", async () => {
  const f = await fixture();
  const accepted = await createSandbox(f.owner, {
    ...f.input,
    expectedDisconnectGraceSeconds: 259200,
  });
  expect(accepted).toMatchObject({
    sandboxHostId: null,
    acceptedGraceSeconds: 259200,
    storagePoolId: null,
    storagePoolName: null,
    storageMarker: null,
  });
  const binding = await requireOwnedSandboxPlacement(db.prisma, f.creatorId, accepted.id);
  expect(binding.hostOwnerId).toBe(f.id);
  expect(binding.placement.hostOwnerId).toBe(f.id);
  const stored = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: accepted.id } });
  expect(stored).toMatchObject({
    userId: f.creatorId,
    hostOwnerId: f.id,
    sandboxHostId: f.host.id,
    usagePoolId: f.pool.id,
  });
  await expect(requireOwnedSandboxPlacement(db.prisma, f.id, accepted.id)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(
    createSandbox(f.owner, {
      template: f.input.template,
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it.each(["maxMemoryMiB", "maxVcpu", "maxDiskGiB"] as const)(
  "share %s serializes last-unit create across independent keys",
  async (cap) => {
    const f = await fixture();
    await db.inspect.share.update({
      where: { id: f.share.id },
      data: {
        [cap]: cap === "maxMemoryMiB" ? vmLiveMemoryChargeMiB(1024) : cap === "maxVcpu" ? 1 : 33,
      },
    });
    const principals = [];
    for (const name of ["first", "second"]) {
      const key = await createSdkKey(f.owner, {
        name,
        resourceMode: "ALLOWLIST",
        poolMode: "SELECTED",
        hostIds: [],
        templateRevisionIds: [f.revision.id],
        poolIds: [f.pool.id],
        scopes: SERVICE_SCOPES.filter(
          // An allowlist key can hold neither webhooks:write (all-owned only) nor
          // credentials:use without an allowlisted login; host scopes need a host grant.
          (scope) =>
            scope !== "webhooks:write" &&
            scope !== "credentials:use" &&
            scope !== "hosts:execute" &&
            scope !== "hosts:files",
        ),
      });
      const principal = await authenticateSdkKeySecret(key.secret);
      if (!principal) throw new Error("Fixture key inactive");
      principals.push(principal);
    }
    const results = await Promise.allSettled(
      principals.map((principal) =>
        createSandbox(principal, { ...f.input, idempotencyKey: randomUUID() }),
      ),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.find((r) => r.status === "rejected")).toMatchObject({
      reason: {
        data: {
          code: "sandbox.share_quota",
          resource: cap === "maxMemoryMiB" ? "memory" : cap === "maxVcpu" ? "vcpu" : "disk",
          // The winner's usage blocks it; the request alone fits the cap.
          retryable: true,
        },
      },
    });
    expect(await db.inspect.sandbox.count({ where: { userId: f.creatorId } })).toBe(1);
  },
);
it("cold start rechecks live quota, retains root quota and never shrinks accepted grace", async () => {
  const f = await fixture();
  const s = await createSandbox(f.owner, f.input);
  await stop(f, s.id);
  await db.inspect.share.update({
    where: { id: f.share.id },
    data: { maxMemoryMiB: 1, maxDiskGiB: 1 },
  });
  await expect(
    reconnectSandbox(f.owner, { id: s.id, mode: "cold", idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({
    // The sandbox alone now exceeds the lowered cap: permanent.
    data: { code: "sandbox.share_quota", resource: "memory", retryable: false },
  });
  await db.inspect.share.update({ where: { id: f.share.id }, data: { maxMemoryMiB: null } });
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { disconnectGraceSeconds: 0 },
  });
  await reconnectSandbox(f.owner, { id: s.id, mode: "cold", idempotencyKey: randomUUID() });
  const binding = await requireOwnedSandboxPlacement(db.prisma, f.creatorId, s.id);
  expect(binding.placement.acceptedGraceSeconds).toBe(259200);
  expect(binding.placement.hostOwnerId).toBe(f.id);
});
it("grace increases improve acceptance; a decreased quote refuses without rows and replay survives revoke", async () => {
  const f = await fixture();
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { disconnectGraceSeconds: 10 },
  });
  await expect(
    createSandbox(f.owner, { ...f.input, expectedDisconnectGraceSeconds: 11 }),
  ).rejects.toMatchObject({ data: { code: "sandbox.pool_policy_changed" } });
  const input = { ...f.input, expectedDisconnectGraceSeconds: 0 };
  expect((await createSandbox(f.owner, input)).acceptedGraceSeconds).toBe(10);
  await db.inspect.share.delete({ where: { id: f.share.id } });
  expect((await createSandbox(f.owner, input)).acceptedGraceSeconds).toBe(10);
  expect(await db.inspect.sandbox.count({ where: { userId: f.creatorId } })).toBe(1);
});
it.each(["memoryCapPercent", "vcpuCapPercent"] as const)(
  "contributed member %s agrees in candidate and cold admission; host-owner pool bypasses only this cap",
  async (cap) => {
    const f = await fixture();
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: f.creatorId, slug: randomUUID(), label: "Inverse pool" },
    });
    const consent = await db.inspect.share.create({
      data: {
        poolId: pool.id,
        ownerUserId: f.creatorId,
        granteeUserId: f.id,
        canUse: false,
        canContribute: true,
      },
    });
    const member = await db.inspect.sandboxPoolMember.create({
      data: {
        userId: f.creatorId,
        hostOwnerId: f.id,
        poolId: pool.id,
        sandboxHostId: f.host.id,
        shareId: consent.id,
        contributeWitness: true,
        ownHostsOnlyWitness: false,
        [cap]: 1,
      },
    });
    const input = { ...f.input, poolId: pool.id };
    // A 1% member cap is below this request even on an empty host.
    await expect(createSandbox(f.owner, input)).rejects.toMatchObject({
      data: {
        code: "sandbox.member_quota",
        resource: cap === "memoryCapPercent" ? "memory" : "vcpu",
        retryable: false,
      },
    });
    await db.inspect.sandboxPoolMember.update({ where: { id: member.id }, data: { [cap]: null } });
    const accepted = await createSandbox(f.owner, input);
    await stop(f, accepted.id);
    await db.inspect.sandboxPoolMember.update({
      where: { id: member.id },
      data: { [cap]: 1, enabled: false },
    });
    await expect(
      reconnectSandbox(f.owner, { id: accepted.id, mode: "cold", idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({ data: { code: "sandbox.member_quota", retryable: false } });
    await db.inspect.sandboxPoolMember.update({ where: { id: member.id }, data: { [cap]: null } });
    await reconnectSandbox(f.owner, {
      id: accepted.id,
      mode: "cold",
      idempotencyKey: randomUUID(),
    });
  },
);
it("revoke-first blocks placement under G before H and leaves no foreign holds", async () => {
  const f = await fixture();
  const pause = db.pauseAt("revoke", { after: /sql:SELECT id FROM sandbox_pool WHERE id = ANY/ });
  const revoke = db.run("revoke", () =>
    db.prisma.$transaction(async (tx) => {
      const { lockPoolGraph } = await import("./pool-locks");
      await lockPoolGraph(tx, [f.pool.id]);
      await tx.share.delete({ where: { id: f.share.id } });
    }),
  );
  await pause.waitReached();
  const placement = db.run("placement", () => createSandbox(f.owner, f.input));
  const refusal = expect(placement).rejects.toMatchObject({ status: 404 });
  try {
    await db.waitUntilBlocked("placement", { by: "revoke" });
  } finally {
    pause.release();
  }
  await revoke;
  await refusal;
  expect(await db.inspect.sandbox.count({ where: { userId: f.creatorId } })).toBe(0);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).rootCount,
  ).toBe(0);
});
it("pool-context registration works without an owned host and transmits only exact public image identity", async () => {
  const f = await fixture();
  const { bindHostImageVerifier } = await import("./host-image-verifier");
  const { createTemplate } = await import("./services/templates");
  const { createTemplateInput } = await import("./template-input");
  const member = await db.inspect.sandboxPoolMember.findFirstOrThrow({
    where: { poolId: f.pool.id, sandboxHostId: f.host.id },
  });
  const requests: unknown[] = [];
  bindHostImageVerifier(async (request) => {
    requests.push(request);
    return { incusFingerprint: f.revision.incusFingerprint, architecture: f.revision.architecture };
  });
  try {
    const input = createTemplateInput.parse({
      poolId: f.pool.id,
      memberId: member.id,
      slug: "pool-image",
      label: "Creator image",
      imageRef: f.revision.incusFingerprint,
      envs: { PRIVATE: "private-image-default-sentinel" },
    });
    const result = await createTemplate(f.owner, input);
    const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
      where: { revisionId: result.firstRevisionId },
    });
    expect(availability).toMatchObject({
      userId: f.creatorId,
      hostOwnerId: f.id,
      hostId: f.host.id,
      status: "AVAILABLE",
    });
    expect(requests).toEqual([
      {
        ownerId: f.id,
        hostId: f.host.id,
        imageRef: f.revision.incusFingerprint,
        expectedArchitecture: f.revision.architecture,
      },
    ]);
    expect(JSON.stringify(requests)).not.toContain("private-image-default-sentinel");
    await expect(
      createTemplate(f.owner, {
        ...input,
        slug: "foreign-direct",
        poolId: undefined,
        memberId: undefined,
        hostId: f.host.id,
      }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(
      createTemplateInput.safeParse({ ...input, imageRef: "images:ubuntu/26.04/cloud" }).success,
    ).toBe(false);
  } finally {
    bindHostImageVerifier(null);
  }
});
it("revocation during image IO cannot store foreign availability or a logical template", async () => {
  const f = await fixture();
  const { bindHostImageVerifier } = await import("./host-image-verifier");
  const { createTemplate } = await import("./services/templates");
  const { createTemplateInput } = await import("./template-input");
  const member = await db.inspect.sandboxPoolMember.findFirstOrThrow({
    where: { poolId: f.pool.id, sandboxHostId: f.host.id },
  });
  bindHostImageVerifier(async () => {
    await db.inspect.share.delete({ where: { id: f.share.id } });
    return { incusFingerprint: f.revision.incusFingerprint, architecture: f.revision.architecture };
  });
  try {
    await expect(
      createTemplate(
        f.owner,
        createTemplateInput.parse({
          poolId: f.pool.id,
          memberId: member.id,
          slug: "revoked-image",
          label: "Refused image",
          imageRef: f.revision.incusFingerprint,
        }),
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(
      await db.inspect.sandboxTemplate.count({
        where: { userId: f.creatorId, slug: "revoked-image" },
      }),
    ).toBe(0);
  } finally {
    bindHostImageVerifier(null);
  }
});
it("placement-first revoke waits on G, retains accepted holds and immediately denies guest IO", async () => {
  const f = await fixture();
  const pause = db.pauseAt("placement", {
    after: /sql:SELECT id FROM sandbox_pool WHERE id = ANY/,
  });
  const placement = db.run("placement", () => createSandbox(f.owner, f.input));
  await pause.waitReached();
  const revoke = db.run("revoke", () =>
    db.prisma.$transaction(async (tx) => {
      const { lockPoolGraph } = await import("./pool-locks");
      await lockPoolGraph(tx, [f.pool.id]);
      await tx.share.delete({ where: { id: f.share.id } });
    }),
  );
  try {
    const blocked = await db.waitUntilBlocked("revoke", { by: "placement" });
    expect(blocked.query).toMatch(/sandbox_pool/);
  } finally {
    pause.release();
  }
  const accepted = await placement;
  await revoke;
  const { authorizeServiceAction } = await import("../lib/sdk-key-access");
  await expect(
    authorizeServiceAction(f.owner, "commands.run", { sandboxId: accepted.id }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect(
    await db.inspect.sandbox.findUnique({
      where: { id: accepted.id },
      select: { liveResourcesHeld: true, diskReservationHeld: true },
    }),
  ).toEqual({ liveResourcesHeld: true, diskReservationHeld: true });
});
it("SDK foreign-host exemption is recomputed for a reused context and cannot outlive member disablement", async () => {
  const f = await fixture();
  const key = await createSdkKey(f.owner, {
    name: "pool-only",
    resourceMode: "ALLOWLIST",
    poolMode: "SELECTED",
    hostIds: [],
    templateRevisionIds: [f.revision.id],
    poolIds: [f.pool.id],
    scopes: SERVICE_SCOPES.filter(
      // An allowlist key can hold neither webhooks:write (all-owned only) nor
      // credentials:use without an allowlisted login; host scopes need a host grant.
      (scope) =>
        scope !== "webhooks:write" &&
        scope !== "credentials:use" &&
        scope !== "hosts:execute" &&
        scope !== "hosts:files",
    ),
  });
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("Fixture key inactive");
  const { authorizeServiceAction } = await import("../lib/sdk-key-access");
  const context = {
    sandboxHostId: f.host.id,
    originPoolId: f.pool.id,
    templateRevisionId: f.revision.id,
  };
  await authorizeServiceAction(principal, "sandboxes.create", context);
  await db.inspect.sandboxPoolMember.updateMany({
    where: { poolId: f.pool.id, sandboxHostId: f.host.id },
    data: { enabled: false },
  });
  await expect(
    authorizeServiceAction(principal, "sandboxes.create", context),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  const ownHost = await db.inspect.sandboxHost.create({
    data: { userId: f.creatorId, slug: randomUUID(), label: "Ungrantable host" },
  });
  const { createTemplate } = await import("./services/templates");
  const { createTemplateInput } = await import("./template-input");
  for (const hostId of [ownHost.id, randomUUID()])
    await expect(
      createTemplate(
        principal,
        createTemplateInput.parse({
          hostId,
          slug: "ungranted",
          label: "Unobservable host",
          imageRef: "local:base",
        }),
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
});
it("foreign image verification never acquires the transport owner's placement advisory after G", async () => {
  const f = await fixture();
  const { bindHostImageVerifier } = await import("./host-image-verifier");
  const { createTemplate } = await import("./services/templates");
  const { createTemplateInput } = await import("./template-input");
  const member = await db.inspect.sandboxPoolMember.findFirstOrThrow({
    where: { poolId: f.pool.id, sandboxHostId: f.host.id },
  });
  bindHostImageVerifier(async () => ({
    incusFingerprint: f.revision.incusFingerprint,
    architecture: f.revision.architecture,
  }));
  const pause = db.pauseAt("transport", {
    after: /sql:SELECT 1 AS locked FROM pg_advisory_xact_lock/,
  });
  const holder = db.run("transport", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${f.id}, 31))`;
    }),
  );
  await pause.waitReached();
  const registration = db.run("registration", () =>
    createTemplate(
      f.owner,
      createTemplateInput.parse({
        poolId: f.pool.id,
        memberId: member.id,
        slug: "lock-order-image",
        label: "Image",
        imageRef: f.revision.incusFingerprint,
      }),
    ),
  );
  try {
    const result = await Promise.race([
      registration,
      db.waitUntilBlocked("registration", { by: "transport" }).then(() => {
        throw new Error("Image verification acquired the transport placement advisory after G");
      }),
    ]);
    expect(result).toHaveProperty("firstRevisionId");
  } finally {
    pause.release();
    await holder;
    await registration.catch(() => undefined);
    bindHostImageVerifier(null);
  }
});
it("the creating P-only SDK key loses use after P to Q attribution (warm and cold need Q selected, §5a W1)", async () => {
  const f = await fixture();
  const key = await createSdkKey(f.owner, {
    name: "P-only",
    resourceMode: "ALLOWLIST",
    poolMode: "SELECTED",
    hostIds: [],
    templateRevisionIds: [f.revision.id],
    poolIds: [f.pool.id],
    scopes: SERVICE_SCOPES.filter(
      // An allowlist key can hold neither webhooks:write (all-owned only) nor
      // credentials:use without an allowlisted login; host scopes need a host grant.
      (scope) =>
        scope !== "webhooks:write" &&
        scope !== "credentials:use" &&
        scope !== "hosts:execute" &&
        scope !== "hosts:files",
    ),
  });
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("Fixture key inactive");
  const s = await createSandbox(principal, f.input);
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: randomUUID(), label: "Q" },
  });
  await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: f.id, granteeUserId: f.creatorId },
  });
  const member = await db.inspect.sandboxPoolMember.create({
    data: { poolId: pool.id, userId: f.id, hostOwnerId: f.id, sandboxHostId: f.host.id },
  });
  // Attribution itself is qualified in sharing-access.pg.test.ts. This fixture
  // isolates the new/cold versus retained warm-authority boundary.
  await db.inspect.sandbox.update({
    where: { id: s.id },
    data: { state: "READY", usagePoolId: pool.id, usageMemberId: member.id },
  });
  await db.inspect.share.delete({ where: { id: f.share.id } });
  await expect(
    reconnectSandbox(principal, { id: s.id, mode: "warm", idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect(principal.allowedPoolIds).toEqual(new Set());
  await stop(f, s.id);
  await expect(
    reconnectSandbox(principal, { id: s.id, mode: "cold", idempotencyKey: randomUUID() }),
  ).rejects.toMatchObject({ status: 404 });
});
it("round-2 P1-1: placement never reuses a distributed foreign copy whose access was lost", async () => {
  const f = await fixture();
  const features = {
    egressPolicy: true,
    terminal: true,
    image: { fetch: true, acceptForeign: true },
  };
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonFeatures: features },
  });
  // The creator's image reached the contributed host through the image cache.
  const copy = await db.inspect.sandboxHostImageCache.create({
    data: {
      hostId: f.host.id,
      hostOwnerId: f.id,
      imageOwnerId: f.creatorId,
      fingerprint: f.revision.incusFingerprint,
      compressedBytes: 4096n,
      origin: "fetched",
      connectionEpoch: f.host.connectionEpoch,
      reportedAt: new Date(),
    },
  });
  const create = () => createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
  const missing = { data: { code: "sandbox.template_image_missing" } };
  // The scan marked it lost while the availability row is still AVAILABLE.
  await db.inspect.sandboxHostImageCache.update({
    where: { id: copy.id },
    data: { accessLostAt: new Date() },
  });
  await expect(create()).rejects.toMatchObject(missing);
  // Unmarked, but the owner's policy is now owned-nodes-only.
  await db.inspect.sandboxHostImageCache.update({
    where: { id: copy.id },
    data: { accessLostAt: null },
  });
  await db.inspect.accountImagePolicy.create({
    data: { userId: f.creatorId, imagePlacement: "OWNED_NODES_ONLY" },
  });
  await expect(create()).rejects.toMatchObject(missing);
  // The host stopped accepting foreign images.
  await db.inspect.accountImagePolicy.update({
    where: { userId: f.creatorId },
    data: { imagePlacement: "ANY_NODE" },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonFeatures: { egressPolicy: true, terminal: true } },
  });
  await expect(create()).rejects.toMatchObject(missing);
  // Every gate holds again: the copy is reusable.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonFeatures: features },
  });
  await expect(create()).resolves.toMatchObject({ id: expect.any(String) });
});
