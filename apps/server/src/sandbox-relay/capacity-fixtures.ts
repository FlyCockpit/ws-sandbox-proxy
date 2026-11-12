import {
  hostHelloV11Schema,
  hostStaticCapacityV11Schema,
  VM_SIZE_LIMITS,
} from "@wssp/sandbox-contracts";

/** Strict wire doubles share the same static tuple as seedLaunchHost. */
export function capacityFixture(hostId: string) {
  return hostStaticCapacityV11Schema.parse({
    vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
    storagePools: [
      {
        name: "default",
        marker: hostId === "host-1" ? "a".repeat(32) : `marker_${hostId}`,
        health: "healthy",
        reason: null,
        totalBytes: null,
        usedBytes: null,
        freeBytes: null,
        capacityGiB: 8192,
        capacitySource: "explicit",
        totalBasedCapacityGiB: null,
        derivationTotalBytes: null,
        derivationFreeBytes: null,
        derivationCommittedBytes: null,
        derivationActualBytes: null,
        derivationHeadroomBytes: null,
        implicitCeilingGiB: null,
        draining: false,
      },
    ],
  });
}
export function helloFixture(hostId: string, terminal = false) {
  return hostHelloV11Schema.parse({
    type: "hello",
    id: "hello",
    protocolVersion: "1.0",
    supportedProtocolVersions: ["1.0"],
    daemon: {
      hostId,
      label: "Fixture host",
      capabilities: {
        protocolVersion: "1.0",
        binaryFrames: true,
        cancellation: true,
        operationWal: true,
        hostInventory: true,
        maxBinaryChunkBytes: 1048576,
        streamWindowChunks: 4,
        runtimeKind: "fake",
        egressPolicy: true,
        terminal,
        hostTerminal: false,
        requireHostTerminalTotp: true,
        policyRevision: 0,
        hostManagedSandboxCeiling: VM_SIZE_LIMITS.hostManagedSandboxCeiling,
        maxLeaseMs: 86_400_000,
        egress: { open: false, guard: false },
        maxOutputChunkBytes: 65536,
        censusEntryResults: true,
        pendingReceipts: true,
        expiryStatusResults: true,
        observationFence: true,
        commandRetire: true,
      },
    },
    inventory: { hostId, schedulable: true, sandboxCount: 0 },
    ...capacityFixture(hostId),
  });
}
