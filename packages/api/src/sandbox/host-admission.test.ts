import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { isLiveResourcesReleaseCandidate } = await import("./host-admission.js");

describe("isLiveResourcesReleaseCandidate", () => {
  it("releases on successful stop/kill and failed create", () => {
    expect(
      isLiveResourcesReleaseCandidate({
        kind: "STOP_SANDBOX",
        endState: "stopped",
        opState: "SUCCEEDED",
        sandboxStateBeforeResult: "STOPPING",
      }),
    ).toBe(true);
    expect(
      isLiveResourcesReleaseCandidate({
        kind: "KILL_SANDBOX",
        endState: "deleted",
        opState: "SUCCEEDED",
        sandboxStateBeforeResult: "STOPPING",
      }),
    ).toBe(true);
    expect(
      isLiveResourcesReleaseCandidate({
        kind: "CREATE_SANDBOX",
        opState: "FAILED",
        sandboxStateBeforeResult: "PROVISIONING",
      }),
    ).toBe(true);
  });

  it("keeps slots on unknown outcome and warm reconnect failure", () => {
    expect(
      isLiveResourcesReleaseCandidate({
        kind: "CREATE_SANDBOX",
        opState: "UNKNOWN_OUTCOME",
        sandboxStateBeforeResult: "PROVISIONING",
      }),
    ).toBe(false);
    expect(
      isLiveResourcesReleaseCandidate({
        kind: "RECONNECT_SANDBOX",
        opState: "FAILED",
        sandboxStateBeforeResult: "READY",
      }),
    ).toBe(false);
  });

  it("cold reconnect refusal is a release candidate, subject to predecessor proof", () => {
    expect(
      isLiveResourcesReleaseCandidate({
        kind: "RECONNECT_SANDBOX",
        opState: "FAILED",
        sandboxStateBeforeResult: "STOPPED",
      }),
    ).toBe(true);
  });
});

const { hostVmCapacity, requireHostVmCapacity, assertZeroLiveResources } = await import(
  "./host-admission.js"
);
const capacityHost = {
  liveCount: 0,
  rootCount: 0,
  memoryReservedMiB: 0,
  vcpuReserved: 0,
  daemonMemoryBudgetMiB: 1536,
  daemonVcpuBudget: 4,
  daemonMaxCpuCount: 4,
  connectionEpoch: 1,
  admissionEpoch: 1,
};
it("RAM includes per-VM overhead and vCPU has an independent total budget", () => {
  expect(() =>
    requireHostVmCapacity(capacityHost, { diskGiB: 32, cpuCount: 2, memoryMiB: 1024 }),
  ).not.toThrow();
  expect(() =>
    requireHostVmCapacity(
      { ...capacityHost, memoryReservedMiB: 512 },
      { diskGiB: 32, cpuCount: 2, memoryMiB: 1024 },
    ),
  ).toThrow(
    expect.objectContaining({
      data: { code: "sandbox.host_capacity", reason: "ram", retryable: true },
    }),
  );
  expect(() =>
    requireHostVmCapacity(
      { ...capacityHost, vcpuReserved: 4 },
      { diskGiB: 32, cpuCount: 1, memoryMiB: 512 },
    ),
  ).toThrow(
    expect.objectContaining({
      data: { code: "sandbox.host_capacity", reason: "vcpu", retryable: true },
    }),
  );
  // Within the per-VM maximum but over the host's total vCPU budget on an
  // EMPTY host: no release can make it fit, so the refusal is permanent.
  expect(() =>
    requireHostVmCapacity(
      { ...capacityHost, daemonVcpuBudget: 2 },
      { diskGiB: 32, cpuCount: 3, memoryMiB: 512 },
    ),
  ).toThrow(
    expect.objectContaining({
      data: { code: "sandbox.host_capacity", reason: "vcpu", retryable: false },
    }),
  );
  expect(() =>
    requireHostVmCapacity(
      { ...capacityHost, rootCount: 10_000 },
      {
        diskGiB: 32,
        cpuCount: 1,
        memoryMiB: 512,
      },
      false,
      undefined,
      true,
    ),
  ).toThrow(
    expect.objectContaining({
      data: { code: "sandbox.host_capacity", reason: "ceiling", retryable: true },
    }),
  );
});
it("readiness requires non-null vCPU and held charges add zero while shrink remains visible", () => {
  expect(hostVmCapacity({ ...capacityHost, daemonVcpuBudget: null }).current).toBe(false);
  expect(() =>
    requireHostVmCapacity(
      { ...capacityHost, daemonVcpuBudget: null },
      { diskGiB: 32, cpuCount: 1, memoryMiB: 512 },
    ),
  ).toThrow();
  const held = { ...capacityHost, liveCount: 1, memoryReservedMiB: 1536, vcpuReserved: 4 };
  expect(() =>
    requireHostVmCapacity(held, { diskGiB: 32, cpuCount: 1, memoryMiB: 1024 }, true),
  ).not.toThrow();
  expect(hostVmCapacity({ ...held, daemonMemoryBudgetMiB: 1024 })).toMatchObject({
    memoryOvercommittedMiB: 512,
    memoryAvailableMiB: 0,
  });
});
it("zero-live witness rejects either nonzero weight", () => {
  expect(() => assertZeroLiveResources({ ...capacityHost, vcpuReserved: 1 })).toThrow();
  expect(() => assertZeroLiveResources({ ...capacityHost, memoryReservedMiB: 1 })).toThrow();
});
