vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient, type ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "test-host-token-secret" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { sandboxHostsRouter } = await import("./sandbox-hosts");

const now = new Date("2026-09-17T00:00:00Z");

const hostRow = (overrides: Record<string, unknown> = {}) => ({
  id: "host-1",
  slug: "lab",
  label: "Lab host",
  status: "DISCONNECTED" as const,
  lastConnectedAt: null,
  lastHeartbeatAt: null,
  connectionCount: 0,
  createdAt: now,
  updatedAt: now,
  ...overrides,
});

const hostSummary = {
  id: "host-1",
  slug: "lab",
  label: "Lab host",
  status: "CONNECTED" as const,
  lastConnectedAt: now,
  lastHeartbeatAt: now,
  deletionRequestedAt: null,
};

const deviceCredentialRow = (overrides: Record<string, unknown> = {}) => ({
  id: "device-1",
  lookupPrefix: "wssp_device_prefix",
  sandboxHostId: "host-1",
  lastUsedAt: null,
  revokedAt: null,
  createdAt: now,
  SandboxHost: hostSummary,
  ...overrides,
});

const tokenRow = (overrides: Record<string, unknown> = {}) => ({
  id: "token-1",
  SandboxHost: hostSummary,
  name: "daemon",
  lookupPrefix: "wssp_host_prefix",
  sandboxHostId: "host-1",
  lastUsedAt: null,
  revokedAt: null,
  expiresAt: null,
  createdAt: now,
  ...overrides,
});

function client(userId = "test-user-id") {
  const context: Context = {
    session: {
      user: {
        id: userId,
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: now,
        updatedAt: now,
      },
      session: {
        id: "auth-session",
        userId,
        token: "token",
        expiresAt: new Date("2027-01-01"),
        ipAddress: null,
        userAgent: null,
        createdAt: now,
        updatedAt: now,
      },
    } as Session,
  };
  return createRouterClient(sandboxHostsRouter, { context });
}

/** `hostCaptureHolds`: no template capture holds memory or vCPU on the host. */
const noCaptureHolds = { _sum: { chargedMemoryMiB: null, chargedVcpu: null } };

describe("sandboxHostsRouter — unit (mocked Prisma; no real-DB test yet for the P2003 mapping)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appSetting.findMany.mockResolvedValue([]);
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
  });

  it("rejects unauthenticated listHosts calls", async () => {
    const anonymous = createRouterClient(sandboxHostsRouter, { context: { session: null } });
    await expect(anonymous.listHosts({ limit: 20 })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "UNAUTHORIZED",
    );
    expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
  });

  it("lists owner-scoped hosts", async () => {
    db.sandboxHost.findMany.mockResolvedValue([hostRow()]);
    const result = await client().listHosts({ limit: 20 });
    expect(result.items).toHaveLength(1);
    expect(db.sandboxHost.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          AND: expect.arrayContaining([{ userId: "test-user-id" }]),
        }),
      }),
    );
  });

  it("creates a host for the caller", async () => {
    db.sandboxHost.create.mockResolvedValue(hostRow());
    const result = await client().createHost({ slug: "lab", label: "Lab host" });
    expect(result.slug).toBe("lab");
    expect(db.sandboxHost.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ userId: "test-user-id", slug: "lab" }),
      }),
    );
  });

  it("does not delete another owner's host", async () => {
    db.sandboxHost.findFirst.mockResolvedValue(null);
    await expect(client("user-b").deleteHost({ id: "host-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.sandboxHost.deleteMany).not.toHaveBeenCalled();
  });

  it("deletes an owned host", async () => {
    db.sandboxHost.findFirst.mockResolvedValue({
      id: "host-1",
      userId: "test-user-id",
      connectionEpoch: 1,
      liveCount: 0,
      memoryReservedMiB: 0,
      vcpuReserved: 0,
      rootCount: 0,
      daemonVcpuBudget: 64,
      StoragePools: [],
      daemonMemoryBudgetMiB: 65536,
      daemonMaxCpuCount: 32,
    });
    db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
    db.sandbox.findFirst.mockResolvedValue(null);
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandboxHost.deleteMany.mockResolvedValue({ count: 1 });
    // No in-progress template capture holds resources on the host (E2-A-04).
    db.sandboxTemplateCapture.aggregate.mockResolvedValue(noCaptureHolds as never);
    await expect(client().deleteHost({ id: "host-1" })).resolves.toEqual({
      ok: true,
      pending: false,
    });
    expect(db.sandboxHost.deleteMany).toHaveBeenCalledWith({
      where: {
        id: "host-1",
        userId: "test-user-id",
        liveCount: 0,
        memoryReservedMiB: 0,
        vcpuReserved: 0,
        rootCount: 0,
      },
    });
  });

  it("lists tokens with an owner and host join when hostId is set", async () => {
    db.hostToken.findMany.mockResolvedValue([tokenRow()]);
    const page = await client().listHostTokens({ hostId: "host-1" });
    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).toBeNull();
    expect(db.hostToken.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          AND: [
            {
              userId: "test-user-id",
              sandboxHostId: "host-1",
              SandboxHost: { userId: "test-user-id" },
              revokedAt: null,
            },
          ],
        },
      }),
    );
    expect(page.items[0]).toMatchObject({ id: "token-1", host: hostSummary });
    expect(page.items[0]).not.toHaveProperty("SandboxHost");
  });

  it("does not mint a token for another owner's host", async () => {
    db.sandboxHost.findFirst.mockResolvedValue(null);
    await expect(
      client("user-b").createHostToken({ hostId: "host-1", name: "daemon" }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "NOT_FOUND");
    expect(db.hostToken.create).not.toHaveBeenCalled();
  });

  it("mints a host token for an owned host", async () => {
    const { credentialLookupPrefix, parseHostTokenCredential } = await import(
      "@wssp/db/credential-security"
    );
    const { digestHostTokenSecret, hostTokenListSelect } = await import("../lib/host-token-access");
    db.sandboxHost.findFirst.mockResolvedValue({
      id: "host-1",
      userId: "test-user-id",
      connectionEpoch: 1,
    } as never);
    db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
    db.hostToken.create.mockResolvedValue(tokenRow());
    const result = await client().createHostToken({ hostId: "host-1", name: "daemon" });
    const credential = parseHostTokenCredential(result.secret);
    expect(credential).not.toBeNull();
    expect(result.secret.startsWith("wssp_host_")).toBe(true);
    expect(result.token.name).toBe("daemon");
    const createArgs = db.hostToken.create.mock.calls[0]?.[0];
    expect(createArgs?.select).toEqual(hostTokenListSelect);
    expect(db.hostToken.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userId: "test-user-id",
          sandboxHostId: "host-1",
          lookupPrefix: credentialLookupPrefix(credential!),
          secretDigest: digestHostTokenSecret(credential!),
        }),
      }),
    );
    expect(createArgs?.data.secret).toBeUndefined();
    const serialized = JSON.stringify(result.token);
    expect(serialized).not.toContain(result.secret);
    expect(serialized).not.toContain("secretDigest");
  });

  it("maps host deletion during token mint P2003 to CONFLICT", async () => {
    db.sandboxHost.findFirst.mockResolvedValue({
      id: "host-1",
      userId: "test-user-id",
      connectionEpoch: 1,
    } as never);
    db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
    db.hostToken.create.mockRejectedValueOnce({ code: "P2003" });
    await expect(
      client().createHostToken({ hostId: "host-1", name: "daemon" }),
    ).rejects.toMatchObject({
      code: "CONFLICT",
    });
    expect(db.hostToken.create).toHaveBeenCalledTimes(1);
  });

  it("lists device credentials owner-scoped, paged and without digests", async () => {
    const { hostDeviceCredentialListSelect } = await import("../lib/host-token-access");
    db.hostDeviceCredential.findMany.mockResolvedValue([deviceCredentialRow()]);
    const page = await client().listDeviceCredentials({ limit: 10 });
    expect(page).toEqual({
      items: [
        {
          id: "device-1",
          lookupPrefix: "wssp_device_prefix",
          sandboxHostId: "host-1",
          lastUsedAt: null,
          revokedAt: null,
          createdAt: now,
          host: hostSummary,
        },
      ],
      nextCursor: null,
    });
    const args = db.hostDeviceCredential.findMany.mock.calls[0]?.[0];
    expect(args?.select).toEqual(hostDeviceCredentialListSelect);
    expect(hostDeviceCredentialListSelect).not.toHaveProperty("secretDigest");
    expect(JSON.stringify(args?.where)).toContain('"revokedAt":null');
    expect(args?.where).toEqual({
      AND: [
        {
          userId: "test-user-id",
          SandboxHost: { userId: "test-user-id" },
          revokedAt: null,
        },
      ],
    });
    expect(args?.take).toBe(11);
  });

  it("revokes an owned device credential and returns it without a digest", async () => {
    db.hostDeviceCredential.findFirst.mockResolvedValue({ id: "device-1" });
    db.hostDeviceCredential.updateMany.mockResolvedValue({ count: 1 });
    db.hostDeviceCredential.findFirstOrThrow.mockResolvedValue(
      deviceCredentialRow({ revokedAt: now }),
    );
    const revoked = await client().revokeDeviceCredential({ id: "device-1" });
    expect(revoked).toMatchObject({ id: "device-1", revokedAt: now, host: hostSummary });
    expect(JSON.stringify(revoked)).not.toContain("secretDigest");
    expect(db.hostDeviceCredential.updateMany).toHaveBeenCalledWith({
      where: { id: "device-1", userId: "test-user-id", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it("does not revoke another owner's (or an already revoked) device credential", async () => {
    db.hostDeviceCredential.findFirst.mockResolvedValue(null);
    await expect(client("user-b").revokeDeviceCredential({ id: "device-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.hostDeviceCredential.findFirst).toHaveBeenCalledWith({
      where: { id: "device-1", userId: "user-b", revokedAt: null },
      select: { id: true },
    });
    expect(db.hostDeviceCredential.updateMany).not.toHaveBeenCalled();
    expect(db.hostDeviceCredential.findFirstOrThrow).not.toHaveBeenCalled();
  });

  it("refuses a device credential revoked between the existence check and the write", async () => {
    db.hostDeviceCredential.findFirst.mockResolvedValue({ id: "device-1" });
    db.hostDeviceCredential.updateMany.mockResolvedValue({ count: 0 });
    await expect(client().revokeDeviceCredential({ id: "device-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.hostDeviceCredential.updateMany).toHaveBeenCalledWith({
      where: { id: "device-1", userId: "test-user-id", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it("does not revoke another owner's host token", async () => {
    db.hostToken.findFirst.mockResolvedValue(null);
    await expect(client("user-b").revokeHostToken({ id: "token-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.hostToken.updateMany).not.toHaveBeenCalled();
    expect(db.hostToken.update).not.toHaveBeenCalled();
  });

  it("revoking unknown credential ids allocates no authority state", async () => {
    const { trackedAuthorityKeyCount } = await import("@wssp/db/authority");
    db.hostToken.findFirst.mockResolvedValue(null);
    db.hostDeviceCredential.findFirst.mockResolvedValue(null);
    const before = trackedAuthorityKeyCount();
    for (let i = 0; i < 25; i += 1) {
      await expect(client().revokeHostToken({ id: `missing-token-${i}` })).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
      await expect(
        client().revokeDeviceCredential({ id: `missing-device-${i}` }),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
    }
    expect(trackedAuthorityKeyCount()).toBe(before);
  });
});

it("host deletion removes availability while retaining logical revision history (real DB: host-tombstone.pg.test.ts)", async () => {
  vi.clearAllMocks();
  db.$transaction.mockImplementation(async (work: (tx: typeof db) => Promise<unknown>) => work(db));
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "host-1",
    userId: "test-user-id",
    connectionEpoch: 1,
    liveCount: 0,
    memoryReservedMiB: 0,
    vcpuReserved: 0,
    rootCount: 0,
    daemonVcpuBudget: 64,
    StoragePools: [],
    daemonMemoryBudgetMiB: 65536,
    daemonMaxCpuCount: 32,
  } as never);
  db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
  db.sandboxHost.deleteMany.mockResolvedValue({ count: 1 });
  db.sandbox.findFirst.mockResolvedValue(null);
  db.sandboxOperation.findFirst.mockResolvedValue(null);
  db.sandboxTemplateCapture.aggregate.mockResolvedValue(noCaptureHolds as never);
  expect(await client().deleteHost({ id: "host-1" })).toEqual({ ok: true, pending: false });
  expect(db.sandboxTemplateAvailability.deleteMany).toHaveBeenCalledWith({
    where: { hostId: "host-1", hostOwnerId: "test-user-id" },
  });
  expect(db.sandboxTemplate.updateMany).not.toHaveBeenCalled();
});

it("atomically revokes a host token once, hiding repeat/foreign/missing tokens", async () => {
  vi.clearAllMocks();
  db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
  const revokedRow = {
    id: "token-1",
    name: "daemon",
    lookupPrefix: "abc",
    sandboxHostId: "host-1",
    lastUsedAt: null,
    revokedAt: new Date(),
    expiresAt: null,
    createdAt: new Date(),
  };
  let revoked = false;
  db.hostToken.updateMany.mockImplementation(
    async ({ where }: { where: { id: string; userId: string; revokedAt?: null } }) => {
      if (
        where.id !== "token-1" ||
        where.userId !== "test-user-id" ||
        (where.revokedAt === null && revoked)
      )
        return { count: 0 };
      revoked = true;
      return { count: 1 };
    },
  );
  db.hostToken.findFirstOrThrow.mockResolvedValue(revokedRow);
  db.hostToken.findFirst.mockImplementation(
    async ({ where }: { where: { id: string; userId: string } }) =>
      where.id === "token-1" && where.userId === "test-user-id" && !revoked
        ? { id: "token-1" }
        : null,
  );
  await expect(client("user-b").revokeHostToken({ id: "token-1" })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  const first = client().revokeHostToken({ id: "token-1" });
  const second = client().revokeHostToken({ id: "token-1" });
  await Promise.all([
    expect(first).resolves.toEqual(revokedRow),
    expect(second).rejects.toMatchObject({ code: "NOT_FOUND" }),
  ]);
  expect(db.hostToken.update).not.toHaveBeenCalled();
  expect(db.hostToken.updateMany).toHaveBeenCalledTimes(2);
  expect(db.hostToken.updateMany).toHaveBeenCalledWith({
    where: { id: "token-1", userId: "test-user-id", revokedAt: null },
    data: { revokedAt: expect.any(Date) },
  });
});

describe("updateHost ownership contract (unit; real-DB capacity/lock proofs: apps/server/src/sandbox-api/host-edit.pg.test.ts)", () => {
  it.each([
    ["id-only", {}],
    ["label", { label: "renamed" }],
    ["capacity", {}],
  ])(
    "hides a missing or foreign host as NOT_FOUND before any lock or write (%s)",
    async (_name, fields) => {
      vi.clearAllMocks();
      db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
      db.sandboxHost.findFirst.mockResolvedValue(null);
      await expect(client("user-b").updateHost({ id: "host-1", ...fields })).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
      expect(db.sandboxHost.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: "host-1", userId: "user-b" } }),
      );
      expect(db.sandboxHost.updateMany).not.toHaveBeenCalled();
      expect(db.sandboxHost.update).not.toHaveBeenCalled();
    },
  );
});

it("host picker excludes active membership in the owned pool before pagination", async () => {
  db.sandboxPool.findMany.mockResolvedValue([{ id: "pool-1", userId: "test-user-id" }] as never);
  db.sandboxHost.findMany.mockResolvedValue([]);
  await client().listHosts({ limit: 100, excludePoolId: "pool-1" });
  expect(db.sandboxHost.findMany).toHaveBeenCalledWith(
    expect.objectContaining({
      take: 101,
      where: expect.objectContaining({
        AND: expect.arrayContaining([
          expect.objectContaining({
            userId: "test-user-id",
            PoolMemberships: {
              none: { poolId: "pool-1", removedAt: null },
            },
          }),
        ]),
      }),
    }),
  );
});
