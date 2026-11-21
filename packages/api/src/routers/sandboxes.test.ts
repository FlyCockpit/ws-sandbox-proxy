import { digestContextSnapshot, REQUEST_DIGEST_DOMAIN } from "../sandbox/digest-context";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { readFileSync } from "node:fs";
import { createRouterClient, type ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import {
  hashRequestBody,
  hashRevisionDefaultsBody,
  requestDigestMetadata,
} from "../sandbox/idempotency";
import { runCommand as runCommandService } from "../sandbox/services/sandboxes";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { sandboxesRouter } = await import("./sandboxes");

const now = new Date("2026-09-17T00:00:00Z");
const TEMPLATE_FP = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const templateForDispatch = {
  id: "template-1",
  sandboxHostId: "host-1",
  incusFingerprint: TEMPLATE_FP,
  cpuCount: 1,
  memoryMiB: 1024,
  diskGiB: 32,
  defaultDiskGiB: 32,
  minDiskGiB: 32,
  hostOwnerId: "test-user-id",
  currentPlacementId: "placement-1",
  storagePoolId: "storage-1",
  storagePoolName: "default",
  storageMarker: "a".repeat(32),
  rootChargeGiB: 33,
  diskReservationHeld: false,
  chargedMemoryMiB: 1280,
  chargedVcpu: 1,
  architecture: "x86_64",
  guestUid: 1000,
  guestGid: 1000,
  guestHome: "/home/user",
  guestShell: "/bin/bash",
};

const sandboxRow = (overrides: Record<string, unknown> = {}) => ({
  id: "sandbox-1",
  state: "REQUESTED" as const,
  generation: 1,
  originHostId: "host-1",
  templateId: "template-1",
  templateRevisionId: "template-1",
  originPoolId: null,
  sandboxHostId: "host-1",
  liveResourcesHeld: false,
  cpuCount: 1,
  memoryMiB: 1024,
  diskGiB: 32,
  hostOwnerId: "test-user-id",
  currentPlacementId: "placement-1",
  storagePoolId: "storage-1",
  storagePoolName: "default",
  storageMarker: "a".repeat(32),
  rootChargeGiB: 33,
  diskReservationHeld: false,
  chargedMemoryMiB: 1280,
  chargedVcpu: 1,
  leaseExpiresAt: new Date(Date.now() + 3_600_000),
  leaseRevision: 1,
  leaseExpireAction: "STOP",
  leaseExpiresAtRequested: null,
  leaseExpireActionRequested: null,
  leaseExpiresAtEffective: null,
  leaseExpireActionEffective: null,
  metadata: {},
  createdAt: now,
  updatedAt: now,
  lastErrorCode: null,
  userId: "test-user-id",
  SandboxHost: { id: "host-1", userId: "test-user-id", connectionEpoch: 1 },
  CurrentPlacement: {
    id: "placement-1",
    userId: "test-user-id",
    sandboxId: "sandbox-1",
    generation: 1,
    originHostId: "host-1",
    hostOwnerId: "test-user-id",
    storagePoolId: "storage-1",
    storagePoolName: "default",
    storageMarker: "a".repeat(32),
    acceptedGraceSeconds: 0,
  },
  SandboxTemplateRevision: {
    id: "template-1",
    revision: 1,
    retiredAt: null,
    Template: {
      id: "template-1",
      slug: "ubuntu",
      label: "Ubuntu",
      archivedAt: null,
      imagePlacement: "INHERIT",
    },
  },
  Operations: [],
  // Disk offload facts (disk-view.ts): never offloaded.
  purpose: "WORKLOAD",
  diskOffloadId: null,
  cachedOffloadSeq: null,
  offloadPin: "ANY" as const,
  offloadMode: "ON_STOP" as const,
  offloadAfterMs: null,
  lastStoppedAt: null,
  credentialFilesEver: false,
  DiskOffloads: [],
  User: { ImagePolicy: null },
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
  return createRouterClient(sandboxesRouter, { context });
}

describe("sandboxesRouter", () => {
  /**
   * One database clock per test. Placement reads `clock_timestamp()` and then
   * the host row, and refuses a heartbeat newer than that clock (age < 0).
   * The mocks used to take each from the real clock at call time
   * (`new Date()` vs `Date.now() - 1`), so 2 ms of scheduling delay between
   * the two reads (a loaded machine) made the host "unavailable" (CONFLICT).
   */
  let dbNow = new Date();
  beforeEach(() => {
    vi.clearAllMocks();
    dbNow = new Date();
    db.sandbox.findMany.mockResolvedValue([]);
    db.sandboxHostStoragePool.findFirst.mockResolvedValue({ id: "storage-1" } as never);
    db.$queryRaw.mockImplementation(async (query) => {
      const sql = Array.isArray(query) ? query.join("?") : "";
      return sql.startsWith("SELECT id FROM sandbox_host") ||
        sql.startsWith("SELECT id FROM sandbox_instance WHERE") ||
        sql.includes("FROM sandbox_template_availability a JOIN")
        ? [{ id: "locked" }]
        : sql.includes("clock_timestamp()")
          ? [{ now: dbNow }]
          : [];
    });
    db.appSetting.findMany.mockResolvedValue([]);
    db.session.findUnique.mockResolvedValue({ id: "auth-session" } as never);
    // Materialization reads the revision's root taint explicitly (S8).
    db.sandboxTemplateRevision.findFirstOrThrow.mockResolvedValue({
      builtWithRoot: false,
      capturedWithGuestRoot: false,
      builtWithWsspRecipe: false,
    } as never);
    db.sandboxTemplateRevision.findFirst.mockResolvedValue({
      ...templateForDispatch,
      userId: "test-user-id",
      templateId: "template-1",
      revision: 1,
      retiredAt: null,
    } as never);
    db.sandboxPlacement.findFirst.mockResolvedValue({
      ...templateForDispatch,
      artifact: TEMPLATE_FP,
    } as never);
    db.sandboxPlacement.create.mockResolvedValue({ id: "placement-1" } as never);
    db.sandboxTemplateAvailability.findFirst.mockResolvedValue({
      id: "avail-1",
      status: "AVAILABLE",
    } as never);
    db.sandboxRevisionConfig.findFirst.mockImplementation(async () => {
      const { hashRevisionDefaultsBody, requestDigestMetadata } = await import(
        "../sandbox/idempotency"
      );
      return {
        defaultEnvs: {},
        checksum: hashRevisionDefaultsBody({ revisionId: "template-1", env: [] }, "test-user-id"),
        digestScheme: requestDigestMetadata().requestDigestScheme,
        digestKeyId: requestDigestMetadata().requestDigestKeyId,
      } as never;
    });
    db.sandbox.findFirst.mockResolvedValue(sandboxRow());
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });
    db.sandboxHost.findFirst.mockImplementation(
      async ({ where }: { where: { userId?: string; id?: string } }) => {
        if (where.userId === "user-b" || where.id === "host-b") {
          return {
            id: "host-b",
            userId: "user-b",
            connectionEpoch: 1,
            relayProtocolVersion: "1.0",
            relayProtocolEpoch: 1,
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
            lastHeartbeatAt: new Date(dbNow.getTime() - 1),
            admissionEpoch: 1,
            inventoryAcknowledgedEpoch: 1,
            admissionRuntime: "FAKE",
            daemonSchedulable: true,

            daemonFeatures: { egressPolicy: true },
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: 1,
          };
        }
        if (where.id === "host-1" && where.userId === "test-user-id") {
          return {
            id: "host-1",
            userId: "test-user-id",
            connectionEpoch: 1,
            relayProtocolVersion: "1.0",
            relayProtocolEpoch: 1,
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
            lastHeartbeatAt: new Date(dbNow.getTime() - 1),
            admissionEpoch: 1,
            inventoryAcknowledgedEpoch: 1,
            admissionRuntime: "FAKE",
            daemonSchedulable: true,

            daemonFeatures: { egressPolicy: true },
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: 1,
          };
        }
        if (where.id === "host-1" && where.userId === undefined) {
          return {
            id: "host-1",
            userId: "test-user-id",
            connectionEpoch: 1,
            relayProtocolVersion: "1.0",
            relayProtocolEpoch: 1,
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
            lastHeartbeatAt: new Date(dbNow.getTime() - 1),
            admissionEpoch: 1,
            inventoryAcknowledgedEpoch: 1,
            admissionRuntime: "FAKE",
            daemonSchedulable: true,

            daemonFeatures: { egressPolicy: true },
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: 1,
          };
        }
        if (where.id === "host-b") {
          return {
            id: "host-b",
            userId: "user-b",
            connectionEpoch: 1,
            relayProtocolVersion: "1.0",
            relayProtocolEpoch: 1,
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
            lastHeartbeatAt: new Date(dbNow.getTime() - 1),
            admissionEpoch: 1,
            inventoryAcknowledgedEpoch: 1,
            admissionRuntime: "FAKE",
            daemonSchedulable: true,

            daemonFeatures: { egressPolicy: true },
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: 1,
          };
        }
        return {
          id: "host-1",
          userId: where.userId ?? "test-user-id",
          connectionEpoch: 1,
          relayProtocolVersion: "1.0",
          relayProtocolEpoch: 1,
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
          lastHeartbeatAt: new Date(dbNow.getTime() - 1),
          admissionEpoch: 1,
          inventoryAcknowledgedEpoch: 1,
          admissionRuntime: "FAKE",
          daemonSchedulable: true,

          daemonFeatures: { egressPolicy: true },
          journalKeyVersion: 1,
          journalKeyId: requestDigestMetadata().requestDigestKeyId,
          journalKeyAcknowledgedEpoch: 1,
        };
      },
    );
    db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
  });

  it("advertises the deployment lifetime maximum behind the session gate", async () => {
    const { env } = await import("@wssp/env/server");
    const previous = env.SANDBOX_MAX_TIMEOUT_MS;
    try {
      env.SANDBOX_MAX_TIMEOUT_MS = 17 * 60_000;
      expect(await client().getLimits()).toMatchObject({
        sandboxTimeoutMaxMs: 17 * 60_000,
        sandboxTimeoutZero: false,
      });
      env.SANDBOX_MAX_TIMEOUT_MS = null;
      expect(await client().getLimits()).toMatchObject({
        sandboxTimeoutMaxMs: 2_073_600_000,
        sandboxTimeoutZero: true,
      });
      await expect(
        createRouterClient(sandboxesRouter, { context: { session: null } }).getLimits(),
      ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    } finally {
      Object.defineProperty(env, "SANDBOX_MAX_TIMEOUT_MS", {
        value: previous,
        writable: true,
        configurable: true,
      });
    }
  });
  it("a disconnected host never produces a successful live probe even for stored READY", async () => {
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxHost.findFirst.mockResolvedValue({ status: "DISCONNECTED" });
    const { bindHostSandboxProbe } = await import("../sandbox/host-image-verifier");
    const probe = vi.fn().mockResolvedValue("guest_ready");
    bindHostSandboxProbe(probe);
    await expect(client().probeSandbox({ id: "sandbox-1" })).resolves.toEqual({
      state: "unreachable",
    });
    expect(probe).not.toHaveBeenCalled();
    bindHostSandboxProbe(null);
  });

  it("rejects unbounded metadata in browser RPC and native service calls before persistence", async () => {
    const { createSandbox } = await import("../sandbox/services/sandboxes");
    const input = {
      template: "revision/" + "template-1",
      sandboxHostId: "host-1",
      idempotencyKey: "metadata-cap",
      metadata: { value: "x".repeat(1025) },
    };
    await expect(client().createSandbox(input)).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      createSandbox({ kind: "session", ownerId: "test-user-id" }, input),
    ).rejects.toMatchObject({ code: "BAD_REQUEST", data: { code: "sandbox.metadata_invalid" } });
    expect(db.sandbox.create).not.toHaveBeenCalled();
  });

  it.each([
    ["domains as a bare string", { domains: "example.com" }],
    ["cidrs as a bare string", { cidrs: "10.0.0.0/8" }],
    ["an unsupported nested field", { domains: ["example.com"], wildcard: true }],
    ["a null entry", { domains: [null] }],
    [
      "an oversized domains array",
      { domains: Array.from({ length: 129 }, (_, i) => `d${i}.example.com`) },
    ],
  ])("maps malformed egress RPC input (%s) to the stable typed error", async (_label, egress) => {
    await expect(
      client().createSandbox({
        template: "revision/" + "template-1",
        sandboxHostId: "host-1",
        idempotencyKey: `egress-shape-${_label}`,
        egress: egress as never,
      }),
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      data: { code: "sandbox.egress_policy_invalid" },
    });
    expect(db.sandbox.create).not.toHaveBeenCalled();
  });

  it("leaves non-egress RPC input validation generic", async () => {
    await expect(
      client().createSandbox({
        template: 42,
        sandboxHostId: "host-1",
        idempotencyKey: "not-egress",
      } as never),
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      data: expect.objectContaining({ issues: expect.any(Array) }),
    });
    expect(db.sandbox.create).not.toHaveBeenCalled();
  });

  it("rejects create without exact current-host availability", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandboxTemplateAvailability.findFirst.mockResolvedValue(null);
    await expect(
      client().createSandbox({
        template: "revision/" + "template-1",
        sandboxHostId: "host-1",
        idempotencyKey: "wrong-host",
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });

  it("rejects unauthenticated list calls", async () => {
    const anonymous = createRouterClient(sandboxesRouter, { context: { session: null } });
    await expect(anonymous.list({ limit: 20 })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "UNAUTHORIZED",
    );
    expect(db.sandbox.findMany).not.toHaveBeenCalled();
  });

  it("lists owner-scoped sandboxes", async () => {
    db.sandbox.findMany.mockResolvedValue([sandboxRow()]);
    const result = await client().list({ limit: 20 });
    expect(result.items).toHaveLength(1);
    expect(db.sandbox.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          AND: expect.arrayContaining([{ userId: "test-user-id" }]),
        }),
      }),
    );
  });

  it("requests history explicitly; discovery defaults to READY", async () => {
    db.sandbox.findMany.mockResolvedValue([]);
    await client().list({ limit: 20, status: "active" });
    await client().list({ limit: 20, status: "deleted" });
    await client().list({ limit: 20 });
    await client().list({ limit: 20, status: "all" });
    const whereClauses = db.sandbox.findMany.mock.calls.map(([args]) =>
      JSON.stringify(args?.where),
    );
    expect(whereClauses[0]).not.toContain('"DELETED"');
    expect(whereClauses[0]).toContain('"STOPPED"');
    expect(whereClauses[1]).toContain('"state":{"in":["DELETED"]}');
    expect(whereClauses[2]).toContain('"state":{"in":["READY"]}');
    expect(whereClauses[3]).toContain('"DELETED"');
  });

  it("projects the host summary, template revision and latest lifecycle receipt", async () => {
    const host = {
      id: "host-1",
      slug: "alpha",
      label: "Alpha",
      status: "CONNECTED",
      lastConnectedAt: now,
      lastHeartbeatAt: now,
      deletionRequestedAt: null,
      draining: false,
    };
    const receipt = {
      id: "op-1",
      kind: "CREATE_SANDBOX",
      state: "UNKNOWN_OUTCOME",
      errorCode: null,
      createdAt: now,
      completedAt: null,
    };
    db.sandbox.findFirst.mockResolvedValue(
      sandboxRow({
        SandboxHost: host,
        SandboxTemplateRevision: {
          id: "template-1",
          revision: 1,
          retiredAt: now,
          Template: {
            id: "template-1",
            slug: "old",
            label: "Old",
            archivedAt: null,
            imagePlacement: "INHERIT",
          },
        },
        Operations: [receipt],
      }),
    );
    const view = await client().getSandbox({ id: "sandbox-1" });
    expect(view).toMatchObject({
      host,
      template: { id: "template-1", retiredAt: now },
      lastLifecycleOperation: receipt,
    });
    expect(view).not.toHaveProperty("SandboxHost");
    expect(view).not.toHaveProperty("Operations");
    // Owner-scoped: another owner's ID can never match.
    expect(JSON.stringify(db.sandbox.findFirst.mock.calls[0]?.[0]?.where)).toContain(
      '"userId":"test-user-id"',
    );
    const select = db.sandbox.findFirst.mock.calls[0]?.[0]?.select as Record<string, unknown>;
    // Only lifecycle kinds, newest first, one row: never command/file receipts.
    expect(select.Operations).toMatchObject({
      where: {
        kind: {
          in: [
            "CREATE_SANDBOX",
            "KILL_SANDBOX",
            "STOP_SANDBOX",
            "RECONNECT_SANDBOX",
            "RENEW_SANDBOX_LEASE",
          ],
        },
      },
      take: 1,
    });
    expect(JSON.stringify(select.Operations)).not.toMatch(/result|errorDetail|idempotencyKey/);
  });

  it("returns NOT_FOUND for another user's sandbox", async () => {
    db.sandbox.findFirst.mockResolvedValue(null);
    await expect(client().getSandbox({ id: "sandbox-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
  });

  it("creates a sandbox, operation, and outbox row", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandboxTemplateRevision.findFirst.mockResolvedValue({
      ...templateForDispatch,
      userId: "test-user-id",
      templateId: "template-1",
      revision: 1,
      retiredAt: null,
    } as never);
    db.sandboxPlacement.findFirst.mockResolvedValue({
      ...templateForDispatch,
      artifact: TEMPLATE_FP,
    } as never);
    db.sandboxPlacement.create.mockResolvedValue({ id: "placement-1" } as never);
    db.sandboxTemplateAvailability.findFirst.mockResolvedValue({
      id: "avail-1",
      status: "AVAILABLE",
    } as never);
    db.sandboxRevisionConfig.findFirst.mockImplementation(async () => {
      const { hashRevisionDefaultsBody, requestDigestMetadata } = await import(
        "../sandbox/idempotency"
      );
      return {
        defaultEnvs: {},
        checksum: hashRevisionDefaultsBody({ revisionId: "template-1", env: [] }, "test-user-id"),
        digestScheme: requestDigestMetadata().requestDigestScheme,
        digestKeyId: requestDigestMetadata().requestDigestKeyId,
      } as never;
    });
    db.sandbox.create.mockResolvedValue(
      sandboxRow({ state: "REQUESTED", sandboxHostId: "host-1", userId: "test-user-id" }),
    );
    db.sandbox.update.mockResolvedValue(
      sandboxRow({ state: "REQUESTED", sandboxHostId: "host-1", userId: "test-user-id" }),
    );
    db.sandbox.findFirst.mockResolvedValueOnce({
      ...sandboxRow({ userId: "test-user-id" }),
      id: "sandbox-1",
      userId: "test-user-id",
      sandboxHostId: "host-1",
      liveResourcesHeld: false,
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      hostOwnerId: "test-user-id",
      currentPlacementId: "placement-1",
      storagePoolId: "storage-1",
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      rootChargeGiB: 33,
      diskReservationHeld: false,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
    });
    db.sandboxOperation.create.mockResolvedValue({ id: "op-1", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});
    // The created row is read back after materializePlacement commits its writes.
    db.sandbox.findFirstOrThrow.mockResolvedValue(
      sandboxRow({ state: "REQUESTED", sandboxHostId: "host-1", userId: "test-user-id" }),
    );

    db.sandbox.findFirst.mockResolvedValue(
      sandboxRow({ state: "SCHEDULED", userId: "test-user-id" }),
    );
    const result = await client().createSandbox({
      template: "revision/" + "template-1",
      sandboxHostId: "host-1",
      idempotencyKey: "create-1",
    });

    expect(result.state).toBe("REQUESTED");
    expect(db.sandboxOperation.create).toHaveBeenCalled();
    expect(db.outboxEvent.create).toHaveBeenCalled();
    // Omitted guestSudo is requested for a WORKLOAD create; this host fixture
    // does not advertise the capability, so it degrades with a reason.
    expect(db.sandbox.create.mock.calls[0]?.[0]?.data).toMatchObject({
      guestSudoRequested: true,
      guestSudo: false,
      guestSudoReason: "HOST_UNSUPPORTED",
      guestRoot: false,
    });
    expect(db.sandboxTemplateRevision.findFirstOrThrow).toHaveBeenCalledWith({
      where: { id: "template-1", userId: "test-user-id" },
      select: { builtWithRoot: true, capturedWithGuestRoot: true, builtWithWsspRecipe: true },
    });
  });

  it("replays createSandbox on idempotent retry", async () => {
    const { hashRequestBody, requestDigestMetadata } = await import("../sandbox");
    const bodyHash = hashRequestBody(
      {
        template: "revision/" + "template-1",
        sandboxHostId: "host-1",
        idempotencyKey: "create-1",
        timeoutMs: 300000,
        lifecycle: { onTimeout: "kill", autoResume: false },
      },
      {
        ownerId: "test-user-id",
        hostOwnerId: "test-user-id",
        hostId: "host-1",
        authorizingKeyId: null,
      },
    );
    db.sandboxOperation.findFirst.mockResolvedValue({
      kind: "CREATE_SANDBOX",
      id: "op-1",
      sandboxId: "sandbox-1",
      authorizingKeyId: null,
      requestBodyHash: bodyHash,
      ...requestDigestMetadata(),
      digestContext: digestContextSnapshot({
        domain: REQUEST_DIGEST_DOMAIN,
        hostId: "host-1",
        hostOwnerId: "test-user-id",
      }),
      Sandbox: sandboxRow({ state: "SCHEDULED" }),
    });

    db.sandbox.findFirst.mockResolvedValue(
      sandboxRow({ state: "SCHEDULED", userId: "test-user-id" }),
    );
    const result = await client().createSandbox({
      template: "revision/" + "template-1",
      sandboxHostId: "host-1",
      idempotencyKey: "create-1",
    });

    expect(result.state).toBe("SCHEDULED");
    expect(db.sandbox.create).not.toHaveBeenCalled();
  });

  it("readFile queues a GET_FILE operation", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxOperation.create.mockResolvedValue({ id: "op-file", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});

    const result = await client().readFile({
      id: "sandbox-1",
      idempotencyKey: "file-1",
      path: "/root/hello.txt",
    });

    expect(result).toEqual({ operationId: "op-file", state: "QUEUED" });
    expect(db.sandbox.update).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          eventType: "sandbox.file_get_requested",
          payload: expect.objectContaining({
            kind: "file.get",
            path: "/root/hello.txt",
          }),
        }),
      }),
    );
  });

  it("killSandbox moves a ready sandbox to stopping", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxTemplate.findFirst.mockResolvedValue({ ...templateForDispatch });
    db.sandboxOperation.create.mockResolvedValue({ id: "op-1", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });

    const result = await client().killSandbox({
      id: "sandbox-1",
      idempotencyKey: "kill-1",
    });

    expect(result.state).toBe("STOPPING");
    expect(db.outboxEvent.create).toHaveBeenCalled();
    expect(db.sandbox.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "sandbox-1", state: "READY", generation: 1 },
        data: { state: "STOPPING", generation: 2 },
      }),
    );
    expect(db.sandboxPlacement.findFirst).toHaveBeenCalled();
  });

  it("does not replay another owner's idempotency receipt", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandboxRevisionConfig.findFirst.mockResolvedValue({
      defaultEnvs: {},
      checksum: hashRevisionDefaultsBody({ revisionId: "template-1", env: [] }, "user-b"),
      digestScheme: requestDigestMetadata().requestDigestScheme,
      digestKeyId: requestDigestMetadata().requestDigestKeyId,
    } as never);
    db.sandboxTemplate.findFirst.mockResolvedValue({
      ...templateForDispatch,
      sandboxHostId: "host-b",
    });
    db.sandbox.create.mockResolvedValue(
      sandboxRow({ state: "REQUESTED", sandboxHostId: "host-b", userId: "user-b" }),
    );
    db.sandbox.update.mockResolvedValue(
      sandboxRow({ state: "REQUESTED", sandboxHostId: "host-b", userId: "user-b" }),
    );
    db.sandbox.findFirst.mockResolvedValue(
      sandboxRow({
        userId: "user-b",
        sandboxHostId: "host-b",
        hostOwnerId: "user-b",
        SandboxHost: { userId: "user-b" },
      }),
    );
    db.sandboxPlacement.findFirst.mockResolvedValue({
      ...templateForDispatch,
      artifact: TEMPLATE_FP,
      hostOwnerId: "user-b",
    } as never);
    db.sandboxOperation.create.mockResolvedValue({ id: "op-1", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});

    await client("user-b").createSandbox({
      template: "revision/" + "template-1",
      sandboxHostId: "host-b",
      idempotencyKey: "create-1",
    });

    expect(db.sandboxOperation.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          userId: "user-b",
          idempotencyKey: "create-1",
          Sandbox: { userId: "user-b" },
        },
      }),
    );
    expect(db.sandbox.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ userId: "user-b" }),
      }),
    );
  });

  it("rejects createSandbox with another owner's template", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandboxTemplateRevision.findFirst.mockResolvedValue(null);
    await expect(
      client().createSandbox({
        template: "revision/" + "foreign-template",
        sandboxHostId: "host-1",
        idempotencyKey: "create-1",
      }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "NOT_FOUND");
    expect(db.sandbox.create).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });

  it("rejects createSandbox with another owner's host", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandboxTemplateRevision.findFirst.mockResolvedValue({
      ...templateForDispatch,
      userId: "test-user-id",
      templateId: "template-1",
      revision: 1,
      retiredAt: null,
    } as never);
    db.sandboxPlacement.findFirst.mockResolvedValue({
      ...templateForDispatch,
      artifact: TEMPLATE_FP,
    } as never);
    db.sandboxPlacement.create.mockResolvedValue({ id: "placement-1" } as never);
    db.sandboxTemplateAvailability.findFirst.mockResolvedValue({
      id: "avail-1",
      status: "AVAILABLE",
    } as never);
    db.sandboxRevisionConfig.findFirst.mockImplementation(async () => {
      const { hashRevisionDefaultsBody, requestDigestMetadata } = await import(
        "../sandbox/idempotency"
      );
      return {
        defaultEnvs: {},
        checksum: hashRevisionDefaultsBody({ revisionId: "template-1", env: [] }, "test-user-id"),
        digestScheme: requestDigestMetadata().requestDigestScheme,
        digestKeyId: requestDigestMetadata().requestDigestKeyId,
      } as never;
    });
    db.sandboxHost.findFirst.mockResolvedValue(null);
    await expect(
      client().createSandbox({
        template: "revision/" + "template-1",
        sandboxHostId: "foreign-host",
        idempotencyKey: "create-1",
      }),
    ).rejects.toMatchObject({ code: "NOT_FOUND", data: { code: "sandbox.host_not_found" } });
    expect(db.sandbox.create).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });

  it("rejects getOperation for another owner using the sandbox join", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    await expect(client("user-b").getOperation({ operationId: "op-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.sandboxOperation.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: "op-1",
          userId: "user-b",
          Sandbox: { userId: "user-b" },
        },
      }),
    );
  });

  it("getCommandOutput reads one owner-scoped snapshot page and validates its input", async () => {
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    await expect(client("user-b").getCommandOutput({ operationId: "op-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.sandboxOperation.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "op-1", userId: "user-b", Sandbox: { userId: "user-b" } },
      }),
    );
    expect(db.$transaction).toHaveBeenCalledWith(expect.any(Function), {
      isolationLevel: "RepeatableRead",
    });
    db.sandboxOperation.findFirst.mockResolvedValue({
      id: "op-1",
      kind: "RUN_COMMAND",
      state: "RUNNING",
      completedAt: null,
      result: null,
      // Same generation as the sandbox: live, not superseded output.
      generation: 1,
      Sandbox: { generation: 1 },
    } as never);
    db.sandboxCommandOutput.findUnique.mockResolvedValue({
      attempt: 1,
      receivedEnd: 2n,
      totalBytes: null,
      headBytes: 2,
      tailBytes: 0,
    } as never);
    db.sandboxCommandOutputSegment.findMany.mockResolvedValue([
      {
        startOffset: 0n,
        endOffset: 2n,
        bytes: new Uint8Array([0x68, 0x69]),
        stderrMask: new Uint8Array([0b10]),
      },
    ] as never);
    expect(await client().getCommandOutput({ operationId: "op-1", cursor: "1_0" })).toMatchObject({
      chunks: [
        { stream: "stdout", offset: 0, data: "aA==" },
        { stream: "stderr", offset: 1, data: "aQ==" },
      ],
      nextCursor: "1_2",
      complete: false,
    });
    await expect(
      client().getCommandOutput({ operationId: "op-1", maxBytes: 65_537 }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "BAD_REQUEST");
  });

  it("rejects killSandbox for another owner's sandbox", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockImplementationOnce(async () => null);
    await expect(
      client("user-b").killSandbox({ id: "sandbox-1", idempotencyKey: "kill-1" }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "NOT_FOUND");
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
    expect(db.sandbox.update).not.toHaveBeenCalled();
    expect(db.sandbox.updateMany).not.toHaveBeenCalled();
  });

  it.each([
    {
      name: "createSnapshot",
      call: () =>
        client().createSnapshot({
          id: "sandbox-1",
          idempotencyKey: "snap-1",
          snapshotName: "disk-1",
        }),
    },
    {
      name: "restoreSnapshot",
      call: () =>
        client().restoreSnapshot({
          id: "sandbox-1",
          idempotencyKey: "restore-1",
          snapshotName: "disk-1",
        }),
    },
    {
      name: "forkSandbox",
      call: () => client().forkSandbox({ id: "sandbox-1", idempotencyKey: "fork-1" }),
    },
  ] as const)("$name is unsupported and enqueues nothing", async ({ call }) => {
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    await expect(call()).rejects.toSatisfy((error: ORPCError) => {
      const data = error.data as { code?: string } | undefined;
      return error.code === "BAD_REQUEST" && data?.code === "UNSUPPORTED_CAPABILITY";
    });
    expect(db.sandboxOperation.create).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });

  function competingDeletionBetweenReadAndTransaction() {
    const store = {
      state: "DELETED" as string,
      operations: [] as unknown[],
      outbox: [] as unknown[],
    };
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => {
      const tx = {
        sandboxActionReceipt: { findUnique: vi.fn(async () => null) },
        sandboxTransfer: { findUnique: vi.fn(async () => null) },
        // Not a waiting create: the capacity-queue cancel branch is skipped.
        sandboxCapacityWait: { findFirst: vi.fn(async () => null) },
        // Not a waiting restore either (offload §8.3c).
        sandboxRestoreWait: { findFirst: vi.fn(async () => null) },
        $queryRaw: vi.fn(async () => []),
        user: {
          findUnique: vi.fn(async () => ({ deletionRequestedAt: null })),
        },
        sandboxHost: {
          findFirst: vi.fn(async () => ({
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
            daemonMaxLeaseMs: 86_400_000,
          })),
          updateMany: vi.fn(async () => ({ count: 1 })),
        },
        sandbox: {
          findFirst: vi.fn(async () => sandboxRow({ state: store.state })),
          updateMany: vi.fn(async ({ where }: { where: { id?: string; state?: string } }) => {
            if (where.state !== undefined && where.state !== store.state) {
              return { count: 0 };
            }
            store.state = "STOPPING";
            return { count: 1 };
          }),
          update: vi.fn(),
        },
        sandboxOperation: {
          findFirst: vi.fn(async () => null),
          create: vi.fn(async ({ data }: { data: unknown }) => {
            store.operations.push(data);
            return { id: "op-new", state: "QUEUED" };
          }),
        },
        outboxEvent: {
          create: vi.fn(async ({ data }: { data: unknown }) => {
            store.outbox.push(data);
            return {};
          }),
        },
      };
      return fn(tx as unknown as typeof db);
    });
    return store;
  }

  it("stopSandbox CASes READY to STOPPING before enqueue", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandbox.updateMany.mockResolvedValue({ count: 1 });
    db.sandboxOperation.create.mockResolvedValue({ id: "op-stop", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});

    const result = await client().stopSandbox({
      id: "sandbox-1",
      idempotencyKey: "stop-ok",
    });

    expect(result).toEqual({ operationId: "op-stop", state: "QUEUED" });
    expect(db.sandbox.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "sandbox-1", state: "READY", generation: 1 },
        data: { state: "STOPPING", generation: 2 },
      }),
    );
  });

  it("stopSandbox CAS misses a competing deletion and creates nothing", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    const store = competingDeletionBetweenReadAndTransaction();

    await expect(
      client().stopSandbox({ id: "sandbox-1", idempotencyKey: "stop-1" }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "CONFLICT");
    expect(store.state).toBe("DELETED");
    expect(store.operations).toEqual([]);
    expect(store.outbox).toEqual([]);
  });

  it("killSandbox CAS misses a competing deletion and creates nothing", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxTemplate.findFirst.mockResolvedValue({ ...templateForDispatch });
    const store = competingDeletionBetweenReadAndTransaction();

    await expect(
      client().killSandbox({ id: "sandbox-1", idempotencyKey: "kill-race" }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "CONFLICT");
    expect(store.state).toBe("DELETED");
    expect(store.operations).toEqual([]);
    expect(store.outbox).toEqual([]);
  });

  it("guest-work admission CASes sandbox generation/state inside the transaction", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxOperation.create.mockResolvedValue({ id: "op-cmd", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});

    await client().runCommand({
      id: "sandbox-1",
      idempotencyKey: "cmd-cas",
      argv: ["true"],
    });

    expect(db.sandbox.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: "sandbox-1",
          generation: 1,
          state: "READY",
        }),
        data: { generation: 1 },
      }),
    );
  });

  it.each(["command", "warm reconnect", "cold reconnect"])(
    "%s rejects stale admission after destroy",
    async (action) => {
      db.sandboxOperation.findFirst.mockResolvedValue(null);
      const state = { generation: 1, state: action === "cold reconnect" ? "STOPPED" : "READY" };
      db.sandbox.findFirst.mockResolvedValue(sandboxRow({ ...state }));
      let enter!: () => void, release!: () => void;
      const entered = new Promise<void>((r) => {
        enter = r;
      });
      const resume = new Promise<void>((r) => {
        release = r;
      });
      db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => {
        enter();
        await resume;
        return fn(db);
      });
      db.sandbox.updateMany.mockImplementation(
        async ({
          where,
          data,
        }: {
          where: { generation: number; state: string };
          data: { generation: number; state?: string };
        }) => {
          if (where.generation !== state.generation || where.state !== state.state)
            return { count: 0 };
          Object.assign(state, data);
          return { count: 1 };
        },
      );
      const pending =
        action === "command"
          ? client().runCommand({ id: "sandbox-1", idempotencyKey: "race", argv: ["true"] })
          : client().reconnectSandbox({ id: "sandbox-1", idempotencyKey: "race" });
      await entered;
      state.generation = 2;
      state.state = "DELETED";
      release();
      await expect(pending).rejects.toSatisfy((error: ORPCError) => error.code === "CONFLICT");
      expect(db.sandboxOperation.create).not.toHaveBeenCalled();
      expect(db.outboxEvent.create).not.toHaveBeenCalled();
    },
  );

  it("preserves a long script through enqueue and idempotent replay", async () => {
    const fixture = JSON.parse(
      readFileSync(
        new URL(
          "../../../../crates/sandbox-protocol/fixtures/control_operation_dispatch_script.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const input = {
      id: "sandbox-1",
      idempotencyKey: "script-1",
      script: fixture.script as string,
      timeoutMs: 120_000,
    };
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxOperation.create.mockResolvedValue({ id: "op-script", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});
    await client().runCommand(input);
    expect(db.outboxEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          payload: expect.objectContaining({ script: input.script }),
        }),
      }),
    );
    db.sandboxOperation.findFirst.mockResolvedValue({
      id: "op-script",
      state: "QUEUED",
      kind: "RUN_COMMAND",
      authorizingKeyId: null,
      sandboxId: "sandbox-1",
      requestBodyHash: hashRequestBody(input, {
        ownerId: "test-user-id",
        hostOwnerId: "test-user-id",
        hostId: "host-1",
        authorizingKeyId: null,
      }),
      ...requestDigestMetadata(),
      digestContext: digestContextSnapshot({
        domain: REQUEST_DIGEST_DOMAIN,
        hostId: "host-1",
        hostOwnerId: "test-user-id",
      }),
    });
    await expect(client().runCommand(input)).resolves.toEqual({
      operationId: "op-script",
      state: "QUEUED",
    });
    expect(db.sandboxOperation.create).toHaveBeenCalledTimes(1);
    expect(db.outboxEvent.create).toHaveBeenCalledTimes(1);
    await expect(
      client().runCommand({ ...input, script: `${input.script} ` }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it.each(["command", "read file", "stat path"])(
    "replays the same receipt shape for %s",
    async (operation) => {
      const input = { id: "sandbox-1", idempotencyKey: "replay", path: "/file" };
      const body =
        operation === "command"
          ? {
              id: input.id,
              idempotencyKey: input.idempotencyKey,
              argv: ["true"],
              timeoutMs: 120_000,
            }
          : input;
      const kind =
        operation === "command"
          ? "RUN_COMMAND"
          : operation === "read file"
            ? "GET_FILE"
            : "STAT_PATH";
      db.sandboxOperation.findFirst.mockResolvedValue({
        id: "op-replay",
        state: "SUCCEEDED",
        kind,
        authorizingKeyId: null,
        sandboxId: "sandbox-1",
        requestBodyHash: hashRequestBody(body, {
          ownerId: "test-user-id",
          hostOwnerId: "test-user-id",
          hostId: "host-1",
          authorizingKeyId: null,
        }),
        ...requestDigestMetadata(),
        digestContext: digestContextSnapshot({
          domain: REQUEST_DIGEST_DOMAIN,
          hostId: "host-1",
          hostOwnerId: "test-user-id",
        }),
      });
      const result =
        operation === "command"
          ? await client().runCommand({
              id: input.id,
              idempotencyKey: input.idempotencyKey,
              argv: ["true"],
            })
          : operation === "read file"
            ? await client().readFile(input)
            : await client().statPath(input);
      expect(result).toEqual({ operationId: "op-replay", state: "SUCCEEDED" });
      expect(db.sandbox.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: "sandbox-1", userId: "test-user-id" } }),
      );
      expect(db.sandboxOperation.create).not.toHaveBeenCalled();
      expect(db.outboxEvent.create).not.toHaveBeenCalled();
    },
  );

  it.each([
    { script: "x".repeat(32768) },
    {
      script: "true",
      env: Array.from({ length: 8 }, (_, i): [string, string] => [`VAR_${i}`, "z".repeat(4096)]),
    },
    { script: "true", argv: ["true"] },
  ])("rejects invalid command payload before service enqueue", async (parts) => {
    const input = { id: "sandbox-1", idempotencyKey: "invalid", timeoutMs: 120_000, ...parts };
    await expect(client().runCommand(input)).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      runCommandService({ kind: "session" as const, ownerId: "test-user-id" }, input),
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(db.sandboxOperation.create).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });

  it("runCommand does not toggle sandbox lifecycle", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxOperation.create.mockResolvedValue({ id: "op-cmd", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});

    const result = await client().runCommand({
      id: "sandbox-1",
      idempotencyKey: "cmd-1",
      argv: ["false"],
    });

    expect(result).toEqual({ operationId: "op-cmd", state: "QUEUED" });
    expect(db.sandbox.update).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          eventType: "sandbox.command_requested",
          payload: expect.objectContaining({
            kind: "command.run",
            argv: ["false"],
            timeoutMs: 120_000,
          }),
        }),
      }),
    );
  });

  it.each([undefined, false])(
    "writeStdin rejects empty non-EOF (%s) at the API boundary",
    async (eof) => {
      await expect(
        client().writeStdin({ operationId: "op-cmd", contentBase64: "", eof }),
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      expect(db.sandboxOperation.findFirst).not.toHaveBeenCalled();
      expect(db.outboxEvent.create).not.toHaveBeenCalled();
    },
  );

  it("writeStdin accepts empty EOF and reserves its one frame", async () => {
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxOperation.findFirst.mockImplementation(async (args) =>
      args?.where?.idempotencyKey !== undefined
        ? null
        : {
            id: "op-cmd",
            sandboxId: "sandbox-1",
            kind: "RUN_COMMAND",
            generation: 1,
            state: "RUNNING",
            dispatchAttempt: 1,
            dispatchedHostId: "host-1",
            dispatchedConnectionEpoch: 1,
            nextStdinSequence: 0,
            stdinClosed: false,
          },
    );
    db.sandboxHost.findFirst.mockResolvedValue({
      id: "host-1",
      userId: "test-user-id",
      connectionEpoch: 1,
      status: "CONNECTED",
    });
    db.sandboxActionReceipt.create.mockResolvedValue({ id: "stdin-receipt", state: "SUCCEEDED" });
    db.sandboxOperation.updateMany.mockResolvedValue({ count: 1 });
    db.outboxEvent.create.mockResolvedValue({});
    await expect(
      client().writeStdin({ operationId: "op-cmd", contentBase64: "", eof: true }),
    ).resolves.toEqual({ operationId: "op-cmd", eof: true });
    expect(db.sandboxOperation.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { nextStdinSequence: 1, stdinClosed: true },
      }),
    );
    expect(db.outboxEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          payload: expect.objectContaining({ stdinSequence: 0, stdinBase64: "", eof: true }),
        }),
      }),
    );
  });

  it.each([undefined, "", Buffer.alloc(32 * 1024, 7).toString("base64")])(
    "runCommand carries initial stdin in the outbox payload, never the operation row (%#)",
    async (stdinBase64) => {
      db.sandboxOperation.findFirst.mockResolvedValue(null);
      db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
      db.sandboxOperation.create.mockResolvedValue({ id: "op-cmd", state: "QUEUED" });
      db.outboxEvent.create.mockResolvedValue({});
      await client().runCommand({
        id: "sandbox-1",
        idempotencyKey: "initial-stdin",
        argv: ["cat"],
        stdinBase64,
      });
      const created = db.sandboxOperation.create.mock.calls[0]![0].data;
      expect(created).toMatchObject({
        nextStdinSequence: stdinBase64 === undefined ? 0 : 1,
        stdinClosed: stdinBase64 !== undefined,
      });
      expect(Object.keys(created)).not.toContain("payloadBytes");
      const payload = db.outboxEvent.create.mock.calls[0]![0].data.payload as Record<
        string,
        unknown
      >;
      expect(payload.hasStdin).toBe(stdinBase64 !== undefined);
      expect(payload.stdinBase64).toBe(stdinBase64);
    },
  );
  it("runCommand rejects initial stdin above one 32 KiB chunk before any database IO", async () => {
    await expect(
      client().runCommand({
        id: "sandbox-1",
        idempotencyKey: "stdin-too-large",
        argv: ["cat"],
        stdinBase64: Buffer.alloc(32 * 1024 + 1).toString("base64"),
      }),
    ).rejects.toThrow();
    expect(db.sandboxOperation.create).not.toHaveBeenCalled();
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });
  it("runCommand rejects timeoutMs above 1800s", async () => {
    await expect(
      client().runCommand({
        id: "sandbox-1",
        idempotencyKey: "cmd-too-long",
        argv: ["true"],
        timeoutMs: 1_800_001,
      }),
    ).rejects.toThrow();
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });

  it("runCommand persists an explicit timeoutMs", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    db.sandbox.findFirst.mockResolvedValue(sandboxRow({ state: "READY" }));
    db.sandboxOperation.create.mockResolvedValue({ id: "op-cmd-t", state: "QUEUED" });
    db.outboxEvent.create.mockResolvedValue({});

    await client().runCommand({
      id: "sandbox-1",
      idempotencyKey: "cmd-t",
      argv: ["true"],
      timeoutMs: 5_000,
    });

    expect(db.outboxEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          payload: expect.objectContaining({ timeoutMs: 5_000 }),
        }),
      }),
    );
  });

  it("hides another owner's sandbox from unsupported snapshot calls", async () => {
    db.sandbox.findFirst.mockResolvedValue(null);
    await expect(
      client("user-b").createSnapshot({
        id: "sandbox-1",
        idempotencyKey: "snap-1",
        snapshotName: "disk-1",
      }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "NOT_FOUND");
    expect(db.outboxEvent.create).not.toHaveBeenCalled();
  });
});

describe("S0 closed browser gate inventory", () => {
  it("covers all 37 procedures: 18 sensitive and 19 explicit metadata/lifecycle decisions", () => {
    const source = readFileSync(new URL("./sandboxes.ts", import.meta.url), "utf8");
    const entries = [...source.matchAll(/^ {2}(\w+): (\w+Procedure)/gm)].map(([, name, gate]) => [
      name,
      gate,
    ]);
    const sensitive = [
      "getOperationResult",
      "getSandboxCapabilities",
      "connectProcess",
      "killProcess",
      "sendProcessStdin",
      "runCommand",
      "writeStdin",
      "getCommandOutput",
      "readFile",
      "listDir",
      "statPath",
      "mkdir",
      "removePath",
      "movePath",
      "listProcesses",
      "signalProcess",
      "cancelOperation",
      "getOperation",
    ];
    const protectedNames = [
      "list",
      "getSandbox",
      "listOperations",
      "getOperationView",
      "getLimits",
      "probeSandbox",
      "createSandbox",
      "killSandbox",
      "reconnectSandbox",
      "stopSandbox",
      "createSnapshot",
      "restoreSnapshot",
      "forkSandbox",
      "setSandboxTimeout",
      // Rename: owner metadata only, no guest access.
      "updateSandbox",
      // Restore pin (disk offload): owner placement preference, no guest access.
      "setOffloadPin",
      "captureSandbox",
      // Offload §8.7 (U10): re-queue a pending restore cleanup (no guest access).
      "retryCleanup",
      // wssp-ssh §10: the owner's connection audit (metadata only, no guest access).
      "listConnectSessions",
    ];
    expect(entries.sort()).toEqual(
      [
        ...sensitive.map((name) => [name, "liveOwnerSessionProcedure"]),
        ...protectedNames.map((name) => [name, "protectedProcedure"]),
      ].sort(),
    );
  });
});

it.each([
  [{ cpuCount: 0, metadata: { bad: 3 }, egress: { domains: 7 } }, "sandbox.metadata_invalid"],
  [{ memoryMiB: 513, egress: { domains: 7 } }, "sandbox.egress_policy_invalid"],
  [
    { cpuCount: "private-env-sentinel", envs: { PRIVATE: "private-env-sentinel" } },
    "sandbox.vm_size_invalid",
  ],
  [{ memoryMiB: 513 }, "sandbox.vm_size_invalid"],
  [{ name: "Bad_Name" }, "sandbox.name_invalid"],
  [{ name: "wssp-reserved" }, "sandbox.name_invalid"],
] as const)(
  "B5 browser rejects malformed size safely before service IO %j",
  async (fields, code) => {
    // This boundary must translate errors before the handler; no live resource is needed.
    const before = db.sandbox.create.mock.calls.length;
    let caught: unknown;
    try {
      await client().createSandbox({
        template: "base",
        sandboxHostId: "host-1",
        idempotencyKey: "size-invalid",
        ...fields,
      } as never);
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: "BAD_REQUEST", data: { code } });
    expect(JSON.stringify(caught)).not.toContain("private-env-sentinel");
    expect(db.sandbox.create.mock.calls.length).toBe(before);
  },
);
