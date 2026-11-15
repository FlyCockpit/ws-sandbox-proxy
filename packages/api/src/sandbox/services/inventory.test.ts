vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "test-host-token-secret",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { hostTerminalsRouter } = await import("../../routers/host-terminals");
const { sandboxHostsRouter } = await import("../../routers/sandbox-hosts");
const { sandboxTemplatesRouter } = await import("../../routers/sandbox-templates");
const { sandboxesRouter } = await import("../../routers/sandboxes");
const {
  HOST_TERMINAL_PROCEDURE_INVENTORY,
  HOST_PROCEDURE_INVENTORY,
  SANDBOX_PROCEDURE_INVENTORY,
  TEMPLATE_PROCEDURE_INVENTORY,
} = await import("./index");
const { requestDigestMetadata, hashRevisionDefaultsBody } = await import("../idempotency");
const { createSandbox } = await import("./sandboxes");

describe("procedure-to-service inventory", () => {
  it("maps cookie-only host terminal procedures to durable session services", () => {
    expect(Object.keys(hostTerminalsRouter).sort()).toEqual(
      Object.keys(HOST_TERMINAL_PROCEDURE_INVENTORY).sort(),
    );
  });
  it("maps every sandbox procedure to a service function", () => {
    expect(Object.keys(sandboxesRouter).sort()).toEqual(
      Object.keys(SANDBOX_PROCEDURE_INVENTORY).sort(),
    );
    for (const service of Object.values(SANDBOX_PROCEDURE_INVENTORY)) {
      expect(typeof service).toBe("function");
    }
  });

  it("maps every host procedure to a service function", () => {
    expect(Object.keys(sandboxHostsRouter).sort()).toEqual(
      Object.keys(HOST_PROCEDURE_INVENTORY).sort(),
    );
    for (const service of Object.values(HOST_PROCEDURE_INVENTORY)) {
      expect(typeof service).toBe("function");
    }
  });

  it("maps every template procedure to a service function", () => {
    expect(Object.keys(sandboxTemplatesRouter).sort()).toEqual(
      Object.keys(TEMPLATE_PROCEDURE_INVENTORY).sort(),
    );
    for (const service of Object.values(TEMPLATE_PROCEDURE_INVENTORY)) {
      expect(typeof service).toBe("function");
    }
  });
});

describe("SDK principal without a browser session", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.sandboxHostStoragePool.findFirst.mockResolvedValue({ id: "storage-1" } as never);
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
    db.sandboxHost.findFirst.mockResolvedValue({
      id: "host-1",
      userId: "machine-owner",
      connectionEpoch: 1,
      liveCount: 0,
      memoryReservedMiB: 0,
      vcpuReserved: 0,
      rootCount: 0,
      daemonVcpuBudget: 64,
      StoragePools: [],
      daemonMemoryBudgetMiB: 65536,
      daemonMaxCpuCount: 32,
      daemonMaxLeaseMs: 86_400_000,

      egressEnforcement: true,
      daemonEgressGuardOk: true,
      daemonEgressGuardEpoch: 1,
      daemonEgressGuardLeaseUntil: new Date(Date.now() + 60_000),
      daemonOpenEgressForOthers: false,
      status: "CONNECTED",
      lastHeartbeatAt: new Date(Date.now() - 1),
      admissionEpoch: 1,
      inventoryAcknowledgedEpoch: 1,
      daemonSchedulable: true,
      admissionRuntime: "FAKE",

      daemonFeatures: { egressPolicy: true },
      journalKeyVersion: 1,
      journalKeyId: requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: 1,
    });
    db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });
  });

  it("createSandbox records the explicit owner id", async () => {
    db.sdkKey.findUnique.mockResolvedValue({
      id: "key-1",
      userId: "machine-owner",
      resourceMode: "ALL_OWNED",
      scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: {
        banned: false,
        banExpires: null,
        twoFactorEnabled: true,
        createdAt: new Date("2020-01-01"),
        role: "user",
      },
    } as never);

    // Materialization reads the revision's root taint explicitly (S8).
    db.sandboxTemplateRevision.findFirstOrThrow.mockResolvedValue({
      builtWithRoot: false,
      capturedWithGuestRoot: false,
      builtWithWsspRecipe: false,
    } as never);
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    // No live sandbox holds a generated name candidate.
    db.sandbox.findMany.mockResolvedValue([]);
    db.sandboxTemplateRevision.findFirst.mockResolvedValue({
      templateId: "template-1",
      revision: 1,
      retiredAt: null,
      id: "template-1",
      sandboxHostId: "host-1",
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      hostOwnerId: "machine-owner",
      SandboxHost: { userId: "machine-owner" },
      currentPlacementId: "placement-1",
      storagePoolId: "storage-1",
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      rootChargeGiB: 33,
      diskReservationHeld: false,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
      incusFingerprint: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
    });
    db.sandboxTemplateAvailability.findFirst.mockResolvedValue({
      id: "avail",
      status: "AVAILABLE",
    } as never);
    db.sandboxPlacement.create.mockResolvedValue({ id: "placement" } as never);
    db.sandboxPlacement.findFirst.mockResolvedValue({
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      hostOwnerId: "machine-owner",
      SandboxHost: { userId: "machine-owner" },
      currentPlacementId: "placement-1",
      storagePoolId: "storage-1",
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      rootChargeGiB: 33,
      diskReservationHeld: false,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
      artifact: `sha256:${"a".repeat(64)}`,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
    } as never);
    db.sandboxRevisionConfig.findFirst.mockResolvedValue({
      defaultEnvs: {},
      checksum: hashRevisionDefaultsBody({ revisionId: "template-1", env: [] }, "machine-owner"),
      digestScheme: requestDigestMetadata().requestDigestScheme,
      digestKeyId: requestDigestMetadata().requestDigestKeyId,
    } as never);
    db.sandbox.create.mockResolvedValue({
      userId: "machine-owner",
      id: "sandbox-1",
      state: "REQUESTED",
      generation: 1,
      templateId: "template-1",
      templateRevisionId: "template-1",
      originPoolId: null,
      sandboxHostId: "host-1",
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
      metadata: {},
      createdAt: new Date("2026-09-17T00:00:00Z"),
      updatedAt: new Date("2026-09-17T00:00:00Z"),
    });
    db.sandbox.update.mockResolvedValue({
      id: "sandbox-1",
      state: "REQUESTED",
      generation: 1,
      templateId: "template-1",
      templateRevisionId: "template-1",
      originPoolId: null,
      sandboxHostId: "host-1",
      liveResourcesHeld: false,
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      hostOwnerId: "machine-owner",
      SandboxHost: { userId: "machine-owner" },
      currentPlacementId: "placement-1",
      storagePoolId: "storage-1",
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      rootChargeGiB: 33,
      diskReservationHeld: false,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
      metadata: {},
      createdAt: new Date("2026-09-17T00:00:00Z"),
      updatedAt: new Date("2026-09-17T00:00:00Z"),
    });
    db.sandboxOperation.create.mockResolvedValue({ id: "op-1", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});
    db.sandbox.findFirst.mockResolvedValue({
      leaseRevision: 1,
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
      leaseExpireAction: "STOP",
      templateId: "template-1",
      id: "sandbox-1",
      userId: "machine-owner",
      sandboxHostId: "host-1",
      liveResourcesHeld: false,
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      hostOwnerId: "machine-owner",
      SandboxHost: { userId: "machine-owner" },
      currentPlacementId: "placement-1",
      storagePoolId: "storage-1",
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      rootChargeGiB: 33,
      diskReservationHeld: false,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
    });

    await createSandbox(
      {
        kind: "sdkKey",
        credentialKind: "API",
        ownSandboxesOnly: false,
        expiresAt: null,
        keyId: "key-1",
        ownerId: "machine-owner",
        resourceMode: "ALL_OWNED",
        scopes: new Set(["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"]),
        allowedHostIds: "allOwned",
        allowedRevisionIds: "allOwned",
        allowedPoolIds: "allUsable",
      },
      {
        template: "revision/" + "template-1",
        sandboxHostId: "host-1",
        idempotencyKey: "create-1",
      },
    );

    expect(db.sandbox.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ userId: "machine-owner", originHostId: "host-1" }),
      }),
    );
    expect(db.sandboxOperation.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          userId: "machine-owner",
          idempotencyKey: "create-1",
          Sandbox: { userId: "machine-owner" },
        },
      }),
    );
  });
});

describe("C21-READEXIT: every service export is built by the single serviceProcedure boundary", () => {
  it("covers every router inventory entry and every exported service function", async () => {
    const { isServiceProcedure } = await import("../../lib/sdk-key-access");
    const modules = {
      sandboxes: await import("./sandboxes"),
      hosts: await import("./hosts"),
      templates: await import("./templates"),
      sdkKeys: await import("./sdk-keys"),
    };
    const unwrapped: string[] = [];
    for (const [name, module] of Object.entries(modules))
      for (const [exportName, value] of Object.entries(module))
        if (typeof value === "function" && !isServiceProcedure(value))
          unwrapped.push(`${name}.${exportName}`);
    for (const [name, inventory] of Object.entries({
      SANDBOX_PROCEDURE_INVENTORY,
      HOST_PROCEDURE_INVENTORY,
      TEMPLATE_PROCEDURE_INVENTORY,
    }))
      for (const [key, value] of Object.entries(inventory))
        if (!isServiceProcedure(value)) unwrapped.push(`${name}.${key}`);
    expect(unwrapped).toEqual([]);
  });
});
