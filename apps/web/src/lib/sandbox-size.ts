import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import {
  type HostConnectionState,
  hostCapacityState,
  hostConnectionState,
  hostResourceFit,
  type StorageSummary,
  storageDisplayState,
} from "@/lib/host-status";

/**
 * Size and host-choice rules for the Create sandbox page. Everything here is
 * an estimate from discovery that only prevents obvious mistakes; the server
 * decides admission and refuses what does not fit.
 */

/** The largest single sandbox a placement can take now (vCPU, MiB, GiB). */
export type SizeCap = { cpuCount: number; memoryMiB: number; diskGiB: number };

/** Slider snap stops: vCPU, memory in MiB (0.5 to 64 GiB). */
export const CPU_STOPS = [1, 2, 4, 8, 16, 32] as const;
export const MEMORY_STOPS_MIB = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] as const;

const floorStep = (value: number, step: number) => Math.max(0, Math.floor(value / step) * step);

type HostFitFields = Parameters<typeof hostResourceFit>[0];

function usableStorage(host: { storagePools: readonly StorageSummary[] }, at: number) {
  return host.storagePools.filter(
    (pool) => storageDisplayState(pool, at) === "healthy" && !pool.draining,
  );
}

/**
 * A host's largest sandbox from its current report: vCPU within its per-VM
 * maximum and free vCPU, memory within its per-VM maximum and free memory less
 * the VM overhead (256 MiB steps), root disk within the freest healthy storage
 * pool less the root overhead. Null while the report is not current (the page
 * then caps nothing and the server decides). `storageNow` is when the list was
 * read (see `hostResourceFit`).
 */
export function hostSizeCap(
  host: HostFitFields,
  now: number,
  storageNow: number = now,
): SizeCap | null {
  if (hostCapacityState(host, now) !== "current") return null;
  const { capacity } = host;
  const pools = usableStorage(host, storageNow);
  return {
    cpuCount: Math.max(0, Math.min(capacity.maxCpuCount ?? 0, capacity.vcpuAvailable ?? 0)),
    memoryMiB: floorStep(
      Math.min(
        capacity.maxMemoryMiB ?? 0,
        (capacity.memoryAvailableMiB ?? 0) - VM_SIZE_LIMITS.vmHostOverheadMiB,
      ),
      VM_SIZE_LIMITS.memoryMiBStep,
    ),
    diskGiB: Math.max(
      0,
      ...pools.map(
        (pool) => pool.capacityGiB - pool.diskReservedGiB - VM_SIZE_LIMITS.rootDiskOverheadGiB,
      ),
    ),
  };
}

type HostUnavailableReason = "draining" | "storage" | "size" | "ram" | "vcpu" | "disk" | "ceiling";

/**
 * A host as a create choice: available; connected but without a current
 * capacity report (`unmeasured`: selectable, the server decides); reachable
 * only after it reconnects (`offline`, still selectable, named with the Hosts
 * page's own connection state); or unavailable (draining, no healthy storage,
 * or the chosen size does not fit its current report) and not selectable.
 */
export type HostChoice =
  | { kind: "available" }
  | { kind: "unmeasured" }
  | { kind: "offline"; state: HostConnectionState }
  | { kind: "unavailable"; reason: HostUnavailableReason };

export function hostChoice(
  host: HostFitFields & { draining: boolean },
  size: { cpuCount?: number; memoryMiB?: number; diskGiB?: number },
  now: number,
  storageNow: number = now,
): HostChoice {
  if (host.draining) return { kind: "unavailable", reason: "draining" };
  const fit = hostResourceFit(host, size, now, storageNow);
  if (fit !== "unknown" && fit !== "fits") return { kind: "unavailable", reason: fit };
  const state = hostConnectionState(host, now);
  if (state !== "ready") return { kind: "offline", state };
  return hostCapacityState(host, now) === "current"
    ? { kind: "available" }
    : { kind: "unmeasured" };
}

/** Memory in GiB for display ("0.5", "4", "3.75"). */
export function gibFromMib(memoryMiB: number): number {
  return Math.round((memoryMiB / 1024) * 100) / 100;
}
