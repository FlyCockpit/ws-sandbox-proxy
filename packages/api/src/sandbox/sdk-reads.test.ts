vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { hostSchema, sandboxSchema, templateSchema } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { toHostDto, toSandboxDto, toTemplateDto } = await import("./sdk-reads");

const T = new Date("2026-09-26T12:00:00.000Z");
const U = new Date("2026-09-26T13:00:00.000Z");
const sandbox = {
  diskGiB: 32,
  id: "sbx1",
  name: "quiet-otter",
  sandboxHostId: null,
  storagePoolId: null,
  storagePoolName: null,
  storageMarker: null,
  templateId: "tpl1",
  templateRevisionId: "tpl1",
  originPoolId: null,
  cpuCount: 2,
  memoryMiB: 2048,
  state: "READY" as const,
  generation: 1,
  leaseRevision: 2,
  leaseExpiresAt: U,
  leaseExpireAction: "DESTROY" as const,
  leaseExpiresAtRequested: null,
  leaseExpireActionRequested: null,
  leaseExpiresAtEffective: T,
  leaseExpireActionEffective: "STOP" as const,
  metadata: { label: "😀", empty: "" },
  egressPolicy: null,
  egressPolicyHash: null,
  egressRequest: null,
  egressModeReason: null,
  egressDeniedGrants: [],
  guestSudo: true,
  guestSudoRequested: true,
  guestSudoReason: null,
  guestRoot: true,
  // Disk offload facts (disk-view.ts): never offloaded.
  purpose: "WORKLOAD",
  diskOffloadId: null,
  cachedOffloadSeq: null,
  offloadPin: "ANY" as const,
  credentialFilesEver: false,
  DiskOffloads: [],
  User: { ImagePolicy: null },
  SandboxTemplateRevision: { Template: { imagePlacement: "INHERIT" } },
  createdAt: T,
  updatedAt: U,
};

describe("public projections", () => {
  it("maps lease terms, placement loss and metadata into a valid sandbox DTO", () => {
    const dto = toSandboxDto(sandbox);
    expect(sandboxSchema.parse(dto)).toEqual(dto);
    expect(dto.hostId).toBeNull();
    expect(dto.lease).toEqual({
      revision: 2,
      expiresAt: U.toISOString(),
      onExpire: "destroy",
      requested: null,
      effective: { expiresAt: T.toISOString(), onExpire: "stop" },
    });
    expect(dto.metadata).toEqual({ label: "😀", empty: "" });
    // Pre-policy rows disclose deny-all.
    expect(dto.egress).toEqual({ mode: "allowlist", domains: [], cidrs: [] });
    expect(dto.egressRequest).toBeNull();
    expect(dto.egressModeReason).toBeNull();
    expect(dto.egressDeniedGrants).toEqual([]);
    expect(dto).toMatchObject({ guestSudo: true, guestSudoReason: null, guestRoot: true });
  });

  it("maps retired templates and deletion-requested hosts", () => {
    const template = toTemplateDto({
      id: "tpl1",
      sandboxHostId: null,
      storagePoolId: null,
      storagePoolName: null,
      storageMarker: null,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      guestVersion: null,
      archivedAt: T,
      imagePlacement: "INHERIT",
      captureKeep: 3,
      pruneAfterDays: null,
      createdAt: T,
      updatedAt: T,
    });
    expect(templateSchema.parse(template)).toMatchObject({
      archivedAt: T.toISOString(),
    });
    const host = toHostDto({
      ...{ relayProtocolVersion: "1.0", relayProtocolEpoch: 12 },
      id: "host1",
      slug: "lab",
      label: "Lab",
      status: "STALE",
      lastConnectedAt: null,
      lastHeartbeatAt: T,
      capacity: {
        memoryBudgetMiB: null,
        maxCpuCount: null,
        maxMemoryMiB: null,
        memoryReservedMiB: 0,
        memoryAvailableMiB: null,
        memoryOvercommittedMiB: null,
        vcpuBudget: 64,
        vcpuReserved: 0,
        vcpuAvailable: 64,
        vcpuOvercommitted: 0,
        retainedRootCount: 0,
        current: false,
        reportedAt: null,
      },

      liveCount: 0,
      retainedRootCount: 0,
      draining: false,
      egressEnforcement: true,
      egressOpen: false,
      openEgressForOthers: false,
      guestSudoForOthers: true,
      egressGuard: { ok: true, reason: null, leaseActive: true },
      policyReconciler: {
        enabled: true,
        lastPassUnixMs: 1,
        verified: 0,
        drift: 1,
        inconclusive: 0,
        foreign: 0,
        absent: 0,
        pending: 0,
        reportedAt: T.toISOString(),
      },
      deletionRequestedAt: T,
      createdAt: T,
      updatedAt: T,
    });
    expect(hostSchema.parse(host)).toMatchObject({ deletionRequested: true, status: "STALE" });
    expect(host).not.toHaveProperty("relayProtocolVersion");
    expect(host).not.toHaveProperty("relayProtocolEpoch");
    expect(host.policyReconciler).toMatchObject({ drift: 1, reportedAt: T.toISOString() });
  });
});

it.each([
  null,
  [],
  { count: 1 },
  { enabled: true },
  { nil: null },
  { nested: {} },
  { value: "\ud800" },
  JSON.parse('{"__proto__":"bad"}'),
])("rejects invalid stored metadata: %j", (metadata) => {
  expect(() => toSandboxDto({ ...sandbox, metadata })).toThrow();
});

it.each([false, true])("SDK drained requires draining=%s and zero reservations", (draining) => {
  for (const liveCount of [0, 1, 4]) {
    const dto = toHostDto({
      id: "host1",
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      lastConnectedAt: T,
      lastHeartbeatAt: T,
      capacity: {
        memoryBudgetMiB: null,
        maxCpuCount: null,
        maxMemoryMiB: null,
        memoryReservedMiB: 0,
        memoryAvailableMiB: null,
        memoryOvercommittedMiB: null,
        vcpuBudget: 64,
        vcpuReserved: 0,
        vcpuAvailable: 64,
        vcpuOvercommitted: 0,
        retainedRootCount: 0,
        current: false,
        reportedAt: null,
      },

      liveCount,
      retainedRootCount: 0,
      draining,
      egressEnforcement: true,
      egressOpen: false,
      openEgressForOthers: false,
      guestSudoForOthers: true,
      egressGuard: { ok: true, reason: null, leaseActive: true },
      deletionRequestedAt: null,
      createdAt: T,
      updatedAt: T,
    });
    expect(dto.drained).toBe(draining && liveCount === 0);
  }
});

it("keeps every new identity/content/negotiation field out of generic DTOs", async () => {
  const { toOperationDto } = await import("./sdk-reads");
  const { operationSchema } = await import("@wssp/sandbox-contracts");
  const privateFields = {
    processId: "private-process",
    processPid: 123,
    processStartedAt: T,
    processDescriptionExpiresAt: U,
    resultObservedAt: U,
    processBootId: "private-boot",
    processStartTicks: "123",
    processDescription: { cmd: "private-command" },
    resultVersion: 1,
    resultExpiresAt: U,
    scalarResult: { private: true },
    TypedResult: { payload: "private-content" },
    relayProtocolVersion: "1.0",
    relayProtocolEpoch: 12,
  };
  const row = {
    id: "op",
    sandboxId: "sandbox",
    kind: "STAT_PATH" as const,
    state: "SUCCEEDED" as const,
    generation: 1,
    errorCode: null,
    createdAt: T,
    updatedAt: T,
    dispatchedAt: T,
    completedAt: T,
    ...privateFields,
  };
  const projected = toOperationDto({ ...row, failure: { resource: "filesystem", effect: "none" } });
  expect(projected.failure).toEqual({ resource: "filesystem", effect: "none" });
  expect(operationSchema.parse(projected)).toEqual(projected);
  for (const key of Object.keys(privateFields)) expect(projected).not.toHaveProperty(key);
});

it("projects only the fixed readiness label of a guest_unavailable operation", async () => {
  const { toOperationDto } = await import("./sdk-reads");
  const { operationSchema } = await import("@wssp/sandbox-contracts");
  const { readinessFailureRecord } = await import("./readiness-detail");
  const row = {
    id: "op",
    sandboxId: "sandbox",
    kind: "CREATE_SANDBOX" as const,
    state: "FAILED" as const,
    generation: 1,
    errorCode: "guest_unavailable",
    failure: readinessFailureRecord("guest_home"),
    createdAt: T,
    updatedAt: T,
    dispatchedAt: T,
    completedAt: T,
  };
  const projected = toOperationDto(row);
  expect(projected.readinessReason).toBe("guest_home");
  // The record is not a public failure.
  expect(projected.failure).toBeNull();
  expect(operationSchema.parse(projected)).toEqual(projected);
  // Another code, or a record that is not exactly a label, has none.
  expect(toOperationDto({ ...row, errorCode: "internal" })).not.toHaveProperty("readinessReason");
  expect(
    toOperationDto({ ...row, failure: { readinessReason: "guest_home", extra: 1 } }),
  ).not.toHaveProperty("readinessReason");
  expect(() => operationSchema.parse({ ...projected, errorCode: "internal" })).toThrow();
});
